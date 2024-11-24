import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pickle
from globals import IS_CIRCUIT_SETUP

class Client:
    def __init__(self,  message, port=None,  name="",addr="127.0.0.1", ds_addr=globals.DS_ADDR, ds_port=globals.DS_CLIENT_PORT):
        self.port = port
        self.addr = addr
        self.name = name
        self.ds_addr = ds_addr
        self.ds_port = ds_port
        self.thread = threading.Thread(target=self.start_request, args=(message,))
        self.thread.start()
        

    def __str__(self) -> str:
        return self.name
    

    def start_request(self, message):
        """Start the node server to listen for connections on the left port."""
        # Connect to directory and create circuit
        directory_socket = self.connect_to_directory_server()

        # Each node is of the form: [(node_addr, node_port), public_key]
        entry, middle, exit = self.get_circuit(directory_socket) 
        
        # Generate symmetric keys with Diffie Hellman
        entry_symmetric_key = self.exchange_DH_entry_node(entry)
        middle_symmetric_key = self.exhange_DH_middle_node(entry, entry_symmetric_key, middle)
        exit_symmetric_key = self.exchange_DH_exit_node(entry, entry_symmetric_key, middle, middle_symmetric_key, exit)

        message = self.layer_onion(entry, middle, exit, message,("127.0.0.1", globals.DESTINATION_PORT) )
        self.send_message(pickle.dumps(message), entry[0])


    def exchange_DH_entry_node(self, entry_node):
        # Send parameters (g, p)
        parameters = dh.generate_parameters(generator=2, key_size=2048)

        # Generate a and A
        private_key_a = parameters.generate_private_key()
        public_key_A = private_key_a.public_key()

        # Send A
        self.send_message(public_key_A, entry_node[0])

        # Receive B
        entry_node_socket = self.connect_to_entry_node(entry_node)
        public_key_B = self.receive_data_from_entry_node(entry_node_socket)

        # Construct symmetric key 
        shared_key = private_key_a.exchange(public_key_B)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return derived_key


    def connect_to_entry_node(self, entry_node):
        """Connect to the entry node."""
        try:
            entry_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            entry_socket.connect(entry_node[0])
        except socket.error as e:
            print(f"Error connecting to directory server: {e}")
        return entry_socket


    def receive_data_from_entry_node(self, entry_socket):
        data = entry_socket.recv(4096)    # assume data is within 4096 bytes
        entry_socket.close() 
        return pickle.loads(data)


    def exhange_DH_middle_node(self, entry_node, entry_symmetric_key, middle_node):
        # Send parameters (g, p)
        parameters = dh.generate_parameters(generator=2, key_size=2048)

        # Generate c and C
        private_key_c = parameters.generate_private_key()
        public_key_C = private_key_c.public_key()

        # Send C (encrypted with entry_symmetric_key)
        message = [IS_CIRCUIT_SETUP, public_key_C, middle_node[0]]
        fernet_cipher = Fernet(entry_symmetric_key)
        encrypted_message = [fernet_cipher.encrypt(pickle.dumps(x)) for x in message]
        self.send_message(encrypted_message, entry_node[0])

        # Receive D
        entry_node_socket = self.connect_to_entry_node(entry_node)
        public_key_D = self.receive_data_from_middle_entry_node(entry_node_socket, fernet_cipher)

        # Construct symmetric key 
        shared_key = private_key_c.exchange(public_key_D)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return derived_key

    def exchange_DH_exit_node(self, entry_node, entry_symmetric_key, middle_node, middle_symmetric_key, exit_node):
        # Send parameters (g, p)
        parameters = dh.generate_parameters(generator=2, key_size=2048)

        # Generate e and E
        private_key_e = parameters.generate_private_key()
        public_key_E = private_key_e.public_key()

        # Send C (encrypted with entry_symmetric_key)
        message = [IS_CIRCUIT_SETUP, public_key_E, exit_node[0]]
        fernet_cipher_entry = Fernet(entry_symmetric_key)
        fernet_cipher_middle = Fernet(middle_symmetric_key)

        encrypted_message_middle = [fernet_cipher_middle.encrypt(pickle.dumps(x)) for x in message]
        encrypted_message_entry = [fernet_cipher_middle.encrypt(pickle.dumps(x)) for x in encrypted_message_middle]
        self.send_message(encrypted_message_entry, entry_node[0])

        # Receive F
        entry_node_socket = self.connect_to_entry_node(entry_node)
        public_key_F = self.receive_data_from_middle_entry_node(entry_node_socket, fernet_cipher)

        # Construct symmetric key 
        shared_key = private_key_c.exchange(public_key_D)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return derived_key

    def receive_data_from_middle_entry_node(self, entry_socket, symmetric_cipher):
        """Receives data sent by middle node to entry node"""
        data = entry_socket.recv(4096)
        entry_socket.close() 
        return symmetric_cipher.decrypt(pickle.loads(data))


    def connect_to_directory_server(self,):
        """Connect to the directory server and request a key."""
        try:
            directory_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            directory_socket.connect((self.ds_addr, self.ds_port))
            directory_socket.sendall(pickle.dumps("Requesting circuit"))
        except socket.error as e:
            print(f"Error connecting to directory server: {e}")
        return directory_socket


    def send_message(self, message, destination):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as right_socket:
                right_socket.connect(destination)
                right_socket.sendall(message)
                print(f"Sent message to {destination}")
        except socket.error as e:
            print(f"Error connecting ")


        

    def get_circuit(self,directory_socket):
        """
        Listens for the response from the directory server which is a path of nodes.
        """
        data = directory_socket.recv(4096)    # assume data is within 4096 bytes
        directory_socket.close() 
        entry, middle, exit = pickle.loads(data)

        return entry, middle, exit 
        
   
        
    def layer_onion(self,entry, middle, exit, message, destination):
        cipher1 = Fernet(entry[1])
        cipher2 = Fernet(middle[1])
        cipher3 = Fernet(exit[1])

        encrypted_message = [message, destination]

        encrypted_message = [cipher3.encrypt(pickle.dumps(x)) for x in encrypted_message] # this message can be a GET request 

        encrypted_message.append(pickle.dumps(exit[0]))

        encrypted_message = [cipher2.encrypt(x) for x in encrypted_message]

        encrypted_message.append(pickle.dumps(middle[0]))
        # Third encryption
        encrypted_message = [cipher1.encrypt(x) for x in encrypted_message]
        
        ## send this to entry node. 
        return encrypted_message
        

    # Key generation and encryption methods
    def generate_key(self):
        return Fernet.generate_key()

    def encrypt_message(self, message, key):
        cipher = Fernet(key)
        return cipher.encrypt(message)

    def get_key(self, DS_public_key):
        key = self.generate_key()
        encrypted_key = DS_public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

