import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key,Encoding, PublicFormat, ParameterFormat
import pickle
import globals
import queue
import base64
from message import Message, MessageType

class Client:
    def __init__(self, browser_port=globals.BROWSER_PORT, client_right_port=globals.CLIENT_RIGHT_PORT, client_addr="127.0.0.1", ds_addr=globals.DS_ADDR, ds_port=globals.DS_CLIENT_PORT):
        self.my_address = client_addr
        
        # for hostfile for the website
        self.browser_port = browser_port
        self.socket_to_browser: socket.socket = None

        # for getting information back through the circuit, client right port 
        self.client_right_port = client_right_port # TODO: this should be in a thread since the client can have many circuits simultaneously
        
        # to connect to the directory server
        self.ds_addr = ds_addr
        self.ds_port = ds_port
        threading.Thread(target=self.start).start()


    def start(self):
        """Start the tor client
        - Create a socket to listen for browser connections
        - Accept browser connections and ``handle_browser()`` in a separate thread
        """

        # make a socket object with IPv4 addresses (for how addresses are formed) and TCP (packets will be transported)
        self.socket_to_browser = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket (sets itself up) to a specific address and port
        self.socket_to_browser.bind((self.my_address, self.browser_port))

        # Listen for incoming connections
        self.socket_to_browser.listen()
        
        # Accept browser connections and handle them
        while True:
            #listens for and accepts a connection from a client
            browser_socket, (browser_addr, browser_port) = self.accept_browser_connection()
            globals.LOG(f"Connected to browser at {browser_addr}:{browser_port}")
            #spawn a new thread to handle the client
            browser_handler_thread = threading.Thread(target=self.handle_browser, args=(browser_socket,))
            globals.LOG(f"Started thread {browser_handler_thread.name} for browser {browser_addr}:{browser_port}")
            browser_handler_thread.start()
            
            
    def listen_to_node(self, port):
        """
        Listens for incoming connections on the specified port.

        :param port: The port number to listen on.

        Returns the socket
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.my_address, port))
            listen_socket.listen()
            globals.LOG(f"Listening on port {port}...")
            while True:
                client_socket, address = listen_socket.accept()
                return (client_socket, address)


    def get_data(self, socket, address,): 
        '''
        Get data from a socket and return it to handler
        '''
        try:
            data = b''
            while True:
                curr = socket.recv(4096)
                data += curr
                if not curr:
                    globals.LOG(f"Connection with {address} closed.")
                    break
        except socket.error as e:
            globals.LOG(f"Socket error with {address}: {e}")
        finally:
            socket.close()
            return data


    def generate_symmetric_key(self, entry, middle, exit):
        globals.LOG("Generating symmetric keys with Diffie Hellman")
        entry_symmetric_key = self.exchange_DH_entry_node(entry)
        globals.LOG(f"Entry symmetric key established {entry_symmetric_key}")
        middle_symmetric_key = self.exhange_DH_middle_node(entry, entry_symmetric_key, middle)
        globals.LOG(f"Middle symmetric key established {middle_symmetric_key}")
        exit_symmetric_key = self.exchange_DH_exit_node(entry, entry_symmetric_key, middle, middle_symmetric_key, exit)
        globals.LOG(f"Exit symmetric key established {exit_symmetric_key}")    
        return entry_symmetric_key, middle_symmetric_key, exit_symmetric_key


    def relay_messages_bidirectionally(self, browser_socket:socket.socket, directory_socket:socket.socket,entry_node, entry_symmetric_key, middle_node, middle_symmetric_key, exit_node, exit_symmetric_key):
        #browser -> anon network (entry node)
        globals.LOG("############## Relaying messages bidirectionally ##############")
        browser_to_anon_thread = threading.Thread(target=self.relay_messages_from_browser, 
                                                  args=(browser_socket, entry_node, entry_symmetric_key, middle_node, middle_symmetric_key, exit_node, exit_symmetric_key))
        #anon network (entry node) -> browser
        #globals.LOG("Relaying messages bidirectionally")
        #anon_to_browser_thread = threading.Thread(target=self.relay_messages_to_browser, args=(browser_socket,entry_symmetric_key, middle_symmetric_key, exit_symmetric_key))
        #start the threads
        globals.LOG("Starting threads")
        browser_to_anon_thread.start()
        #anon_to_browser_thread.start()
        #wait for the threads to finish (to clean up sockets)
        globals.LOG("Waiting for threads to finish")
        browser_to_anon_thread.join()
        #anon_to_browser_thread.join()
        #close the sockets
        browser_socket.close()
        directory_socket.close()


    def handle_browser(self, browser_socket: socket.socket):
        directory_socket = self.connect_to_directory_server()
        globals.LOG("Connected to directory server")

        # Each node is of the form (addr, left port, right port)
        entry, middle, exit = self.get_circuit(directory_socket) 

        # Generate symmetric keys with Diffie Hellman
        entry_symmetric_key, middle_symmetric_key, exit_symmetric_key = self.generate_symmetric_key(entry, middle, exit)
       
        # Create two threads to relay messages bidirectionally
        self.relay_messages_bidirectionally(browser_socket, directory_socket, entry, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key)
    

    def accept_browser_connection(self):
        """Accept browser connection and return browser socket and address"""
        # block until a browser connects to us.
        # Accepts a browser connection and returns tuple (connection object, addr of browser)
        globals.LOG("Waiting for browser connection")   
        return self.socket_to_browser.accept()
        
    
    def relay_messages_from_browser(self, browser_socket, entry, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key):
        #returns when the source finishes sending data (empty byte string)
        globals.LOG("Relaying messages from browser")
        entry_node_address = (entry[0], entry[1])
        data = b''
        while True:
            packet = browser_socket.recv(1024)
            if not packet:
                break
            data += packet
            globals.LOG(f"Data received from browser{ packet[:10]}")
            # Encrypt message with symmetric keys
            message = self.layer_onion(entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key, data,(globals.DESTINATION_ADDR, globals.DESTINATION_PORT) )
            # Send message to destination
            self.send_message(pickle.dumps(message), entry_node_address)

    # def relay_messages_to_browser(self, browser_socket:socket.socket,entry_symmetric_key, middle_symmetric_key, exit_symmetric_key):
    #      #Get response from destination
         
    #     client_entry_node_socket, client_entry_address = self.listen_to_node(self.client_right_port)
    #     response =  pickle.loads(self.get_data(client_entry_node_socket, client_entry_address)).get_payload()
    #     try:
    #         assert isinstance(response, Message)
    #     except AssertionError:
    #         globals.LOG("Response is not a Message object")
    #         globals.LOG(f"Response {response}") 
         
    # def relay_messages_to_browser(self, browser_socket:socket.socket,entry_symmetric_key, middle_symmetric_key, exit_symmetric_key):
    #      #Get response from destination
    #     response = self.get_response_from_destination_server() # the destination server is the "source" here    
    #     globals.LOG("Response from destination server", response[:10])
    #     # Decrypt message with symmetric keys
    #     self.unlayer_onion(response, entry_symmetric_key, middle_symmetric_key, exit_symmetric_key)
    #     globals.LOG(f"Unlayered response from destination server{ response[:10]}")
    #     # Send response to browser
    #     browser_socket.sendall(response)


    def exchange_DH_entry_node(self, entry_node):
        globals.LOG("############## Exchanging Diffie Hellman keys with entry node ##############")
        
        # Generate parameters and private key 
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key_a = parameters.generate_private_key()
        public_key_A = private_key_a.public_key()
        globals.LOG("Generated parameters and private key")
        
        # Establish addresses
        entry_addr, entry_left_port, _ = entry_node
        entry_left_address = (entry_addr, entry_left_port) # final destination in this function (client's right port sends to entry node's left port)
        client_return_address = (self.my_address, self.client_right_port) # forward back to ourselves (entry node's right port sends to client's right port)

        # Send parameters and public key; pickle every element in message, then pickle the entire list itself
        DH_setup_payload=[public_key_A.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)] # [key, param]
        message = pickle.dumps(Message(DH_setup_payload, client_return_address, MessageType.SETUP))
        self.send_message(message, entry_left_address) #TODO: encrypt with TLS
        globals.LOG("Sent message from client's right to entry node's left")

        # Receive entry node's public key (i.e. B)
        client_entry_node_socket, client_entry_address = self.listen_to_node(self.client_right_port)
        public_key_B =  pickle.loads(self.get_data(client_entry_node_socket, client_entry_address)).get_payload()

        globals.LOG(f"Next {public_key_B[0]}")
        public_key_B = load_der_public_key(public_key_B[0])
        globals.LOG("Received public key B from entry node")
        
        # Construct symmetric key 
        shared_key = private_key_a.exchange(public_key_B)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        globals.LOG("Derived symmetric key")
        return derived_key


    def exhange_DH_middle_node(self, entry_node, entry_symmetric_key, middle_node):
        globals.LOG("############## Exchanging Diffie Hellman keys with middle node ##############")
        
        # Generate parameters and private key (c)
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key_c = parameters.generate_private_key()
        public_key_C = private_key_c.public_key()
        globals.LOG("Generated parameters and private key")

        # Establish addresses
        entry_addr, entry_left_port, entry_right_port = entry_node
        middle_addr, middle_left_port, _ = middle_node
        entry_left_address = (entry_addr, entry_left_port)
        middle_left_address = (middle_addr, middle_left_port)
        entry_right_address = (entry_addr, entry_right_port)
        client_right_address = (self.my_address, self.client_right_port)

        # Send parameters and public key from entry node's right port to middle node's left port; 
        
        # Construct message for entry node to send to middle node. This message will be sent unencrypted along the entry to middle channel [key, param]
        DH_setup_payload=[public_key_C.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)]
        diffie_hellman_message = Message(DH_setup_payload,entry_right_address, MessageType.SETUP)
        
        # Construct message for client to send to entry node to forward the diffie hellman message to the middle node.
        message = Message(diffie_hellman_message,middle_left_address,MessageType.FORWARD)
        
        cipher = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        encrypted_message = cipher.encrypt(pickle.dumps(message))

        self.send_message(pickle.dumps(encrypted_message), entry_left_address)
        globals.LOG("Sent message to entry node with packaged message for middle node.")
        
        # Receive middle node's public key (i.e. D)        
        client_entry_node_socket, client_entry_address = self.listen_to_node(self.client_right_port)
        encrypted_public_key_D = pickle.loads(self.get_data(client_entry_node_socket, client_entry_address))
        
        public_key_D=pickle.loads(cipher.decrypt(encrypted_public_key_D)).get_payload()
        public_key_D = load_der_public_key(public_key_D[0])

        globals.LOG("Received public key D from middle node")

        # Construct symmetric key 
        shared_key = private_key_c.exchange(public_key_D)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        globals.LOG("Derived symmetric key")
        return derived_key


    def exchange_DH_exit_node(self, entry_node, entry_symmetric_key, middle_node, middle_symmetric_key, exit_node):
        globals.LOG("############## Exchanging Diffie Hellman keys with exit node ##############")

        # Generate parameters and private key (e)
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key_e = parameters.generate_private_key()
        public_key_E = private_key_e.public_key()
        globals.LOG("Generated parameters and private key")

        # Establish addresses
        exit_addr, exit_left_port, exit_right_port = exit_node
        middle_addr, middle_left_port, middle_right_port = middle_node
        entry_addr, entry_left_port, entry_right_port = entry_node

        middle_right_address = (middle_addr, middle_right_port)
        exit_left_address = (exit_addr, exit_left_port)
        entry_right_address = (entry_addr, entry_right_port)
        middle_left_address = (middle_addr, middle_left_port)
        entry_left_address = (entry_addr, entry_left_port)
        client_return_address = (self.my_address, self.client_right_port)
        
        
        # Prepare ciphers
        entry_cipher = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        middle_cipher = Fernet(base64.urlsafe_b64encode(middle_symmetric_key))
        
        
        # Construct message for middle node to send to exit node. This message will be sent unencrypted along the middle to exit channel [key, param]
        DH_setup_payload = [public_key_E.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)]
        diffie_hellman_message = Message(DH_setup_payload, middle_right_address, MessageType.SETUP)
        
        # Construct message for entry node to send to middle node (for the middle node to forward to the exit node)
        message = Message(diffie_hellman_message,exit_left_address,MessageType.FORWARD)
        
        encrypted_message_for_middle = middle_cipher.encrypt(pickle.dumps(message))
        
        # Construct message for client to send to entry node. 
        message = Message(encrypted_message_for_middle,middle_left_address,MessageType.FORWARD)
       
        encrypted_message = entry_cipher.encrypt(pickle.dumps(message))

        self.send_message(pickle.dumps(encrypted_message), entry_left_address)
        globals.LOG("Sent message to entry node with packaged message for middle node.")

        # Receive F, which is double encrypted, first by the middle cipher and then by the entry cipher. 
        client_entry_node_socket, client_entry_address = self.listen_to_node(self.client_right_port)
        double_encrypted_public_key_F = pickle.loads(self.get_data(client_entry_node_socket, client_entry_address))
        
        # Remove the first layer of encryption from the entry node.
        encrypted_public_key_F=pickle.loads(entry_cipher.decrypt(double_encrypted_public_key_F))
        
        # Remove the second layer of encryption from the middle node.
        public_key_F=pickle.loads(middle_cipher.decrypt(encrypted_public_key_F)).get_payload()
        
        # Obtain the corresponding public key. 
        public_key_F = load_der_public_key(public_key_F[0])
        globals.LOG("Received public key F from exit node")
        
        # Construct symmetric key 
        shared_key = private_key_e.exchange(public_key_F)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        globals.LOG("Derived symmetric key")
        return derived_key
    

    def connect_to_entry_node(self, entry_node):
        """Connect to the entry node."""
        entry_addr, entry_left_port, entry_right_port = entry_node
        sending_address = (entry_addr, entry_left_port) #entry node's left port
        try:
            entry_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            entry_socket.connect(sending_address)
        except socket.error as e:
            globals.LOG(f"Error connecting to entry node: {e}")
        return entry_socket


    def receive_data_from_exit_via_entry_node(self, entry_socket, entry_symmetric_cipher, middle_symmetric_cipher):
        """Receives data sent by exit node to entry node"""
        data = entry_socket.recv(4096)
        entry_socket.close() 

        return middle_symmetric_cipher.decrypt(entry_symmetric_cipher.decrypt(pickle.loads(data)))


    def connect_to_directory_server(self,):
        """Connect to the directory server and request a key."""
        try:
            directory_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            directory_socket.connect((self.ds_addr, self.ds_port))
            directory_socket.sendall(pickle.dumps("Requesting circuit"))
        except socket.error as e:
            globals.LOG(f"Error connecting to directory server: {e}")
        return directory_socket


    def send_message(self, message, destination):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as right_socket:
                right_socket.connect(destination)
                right_socket.sendall(message)
                globals.LOG(f"Sent message to {destination}")
        except socket.error as e:
            globals.LOG(f"Error connecting {e}")
     

    def get_circuit(self,directory_socket):
        """
        Listens for the response from the directory server which is a path of nodes.
        """
        data = directory_socket.recv(4096)    # assume data is within 4096 bytes
        directory_socket.close() 
        entry, middle, exit = pickle.loads(data)
        #entry = [entry_addr, entry_left_port, entry_right_port]
        return entry, middle, exit 
        
    
    def layer_onion(self, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key, message, destination_server):
        
        # Constructing ciphers
        cipher1 = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        cipher2 = Fernet(base64.urlsafe_b64encode(middle_symmetric_key))
        cipher3 = Fernet(base64.urlsafe_b64encode(exit_symmetric_key))
        
        # Constructing forward addresses
        exit_left_addr = (exit[0], exit[1])
        middle_left_addr = (middle[0], middle[1])
                
        # encrypted_message with cipher 3 for the middle to exit channel 
        message_exit_understands = cipher3.encrypt(pickle.dumps(Message(message, destination_server, MessageType.SERVER)))
        message_middle_understands = cipher2.encrypt(pickle.dumps(Message(message_exit_understands, exit_left_addr, MessageType.FORWARD)))  
        message_entry_understands = cipher1.encrypt(pickle.dumps(Message(message_middle_understands, middle_left_addr, MessageType.FORWARD))) 
        ## send this to entry node. 
        return message_entry_understands
        
    
    def unlayer_onion(self, message, entry_symmetric_key, middle_symmetric_key, exit_symmetric_key):
        # Constructing ciphers
        cipher1 = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        cipher2 = Fernet(base64.urlsafe_b64encode(middle_symmetric_key))
        cipher3 = Fernet(base64.urlsafe_b64encode(exit_symmetric_key))

        decrypt_entry_layer = cipher1.decrypt(pickle.loads(message))
        decrypt_middle_layer = [cipher2.decrypt(x) for x in decrypt_entry_layer[0]]
        decrypt_exit_layer = [cipher3.decrypt(x) for x in decrypt_middle_layer[0]]

        decrypted_message = pickle.loads(decrypt_exit_layer[0])
        return decrypted_message
