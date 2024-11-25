import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pickle
from globals import IS_CIRCUIT_SETUP

class Client:
    def __init__(self, browser_port=8889, client_right_port=None, client_addr="127.0.0.1", ds_addr=globals.DS_ADDR, ds_port=globals.DS_CLIENT_PORT):
        self.my_address = client_addr
        
        #for hostfile for the website
        self.browser_port = browser_port
        self.socket_to_browser: socket.socket = None

        # for getting information back through the circuit, client right port 
        self.client_right_port = client_right_port
        
        # to connect to the directory server
        self.ds_addr = ds_addr
        self.ds_port = ds_port
        self.thread = threading.Thread(target=self.start)
        self.thread.start()

    def start(self):
        """Start the tor client
        - Create a socket to listen for browser connections
        - Accept browser connections and ``handle_browser()`` in a separate thread
        """

        #make a socket object with IPv4 addresses (for how addresses are formed) and TCP (packets will be transported)
        self.socket_to_browser = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket (sets itself up) to a specific address and port
        self.socket_to_browser.bind((self.my_address, self.browser_port))

        # Listen for incoming connections
        self.socket_to_browser.listen()

        # Accept browser connections and handle them
        while True:
            #listens for and accepts a connection from a client
            browser_socket, (browser_addr, browser_port) = self.accept_browser_connection()
            
            #spawn a new thread to handle the client
            browser_handler_thread = threading.Thread(target=self.handle_browser, args=(browser_socket,))
            browser_handler_thread.start()

        
    def handle_browser(self, browser_socket: socket.socket):
        
        directory_socket = self.connect_to_directory_server()

        # Each node is of the form: [(node_addr, node_port), public_key]
        entry, middle, exit = self.get_circuit(directory_socket) 
        
        # Generate symmetric keys with Diffie Hellman
        entry_symmetric_key = self.exchange_DH_entry_node(entry)
        middle_symmetric_key = self.exhange_DH_middle_node(entry, entry_symmetric_key, middle)
        exit_symmetric_key = self.exchange_DH_exit_node(entry, entry_symmetric_key, middle, middle_symmetric_key, exit)
        
        # Create two threads to relay messages bidirectionally
        #browser -> anon network (entry node)
        browser_to_anon_thread = threading.Thread(target=self.relay_messages_from_browser, 
                                                  args=(browser_socket, entry, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key,))
        #anon network (entry node) -> browser
        anon_to_browser_thread = threading.Thread(target=self.relay_messages_to_browser, args=(browser_socket,entry_symmetric_key, middle_symmetric_key, exit_symmetric_key))

        #start the threads
        browser_to_anon_thread.start()
        anon_to_browser_thread.start()

        #wait for the threads to finish (to clean up sockets)
        browser_to_anon_thread.join()
        anon_to_browser_thread.join()

        #close the sockets
        browser_socket.close()
        directory_socket.close()
    
    def accept_browser_connection(self) -> tuple[socket.socket, tuple[str, int]]:
        """Accept browser connection and return browser socket and address"""
        # block until a browser connects to us.
        # Accepts a browser connection and returns tuple (connection object, addr of browser)
        return self.socket_to_browser.accept()
        
    
    def relay_messages_from_browser(self, browser_socket:socket.socket, entry, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key):
        #returns when the source finishes sending data (empty byte string)
        while True:
            data = browser_socket.recv(1024)
            if not data:
                break            
            # Encrypt message with symmetric keys
            message = self.layer_onion( entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key, data,("127.0.0.1", globals.DESTINATION_PORT) )
            # Send message to destination
            self.send_message(pickle.dumps(message), entry[0])

        browser_socket.shutdown(socket.SHUT_WR)
        
    def relay_messages_to_browser(self, browser_socket:socket.socket,entry_symmetric_key, middle_symmetric_key, exit_symmetric_key):
         #Get response from destination
        response = self.get_response_from_destination_server() # the destination server is the "source" here    
        
        # Decrypt message with symmetric keys
        self.unlayer_onion(response, entry_symmetric_key, middle_symmetric_key, exit_symmetric_key)
        
        # Send response to browser
        browser_socket.sendall(response)


    def get_response_from_destination_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.my_address, self.entry_node_port))
            listen_socket.listen()
            while True:
                right_socket, address = listen_socket.accept()
                # Create a new thread for each entry node connection where entry node is transmitting data from the destination server
                right_thread = threading.Thread(
                    target=self.handle_response_from_destination, args=(right_socket, address)
                )
                right_thread.start()
                right_thread.join()

    def handle_response_from_destination(self, right_socket, address):
        """Handle incoming connections"""
        try:
            data = b''
            while True:
                curr = right_socket.recv(4096)
                data += curr
                if not curr:
                    print(f"Connection with {address} closed.")
                    break
            print("Message Received", pickle.loads(data))    
            return pickle.loads(data)  
        except socket.error as e:
            print(f"Socket error with {address}: {e}")
        finally:
            right_socket.close()        

    def exchange_DH_entry_node(self, entry_node):
        # Generate parameters (g, p)
        parameters = dh.generate_parameters(generator=2, key_size=2048)

        # Generate a and A
        private_key_a = parameters.generate_private_key()
        public_key_A = private_key_a.public_key()
        
        entry_addr, entry_left_port, entry_right_port = entry_node
        entry_sending_address = (entry_addr, entry_left_port) #final destination in this function (node 1's left port)
        
        client_return_address = (self.my_address, self.client_right_port) # forward back to ourselves (entry node's right port)

        # construct message as [public_key_A, IS_CIRCUIT_SETUP flag, client_location tuple, parameters]
        message = [public_key_A, IS_CIRCUIT_SETUP, client_return_address, parameters]
        # Send A and parameters
        self.send_message(message, entry_sending_address) #TODO: encrypt with TLS

        # Receive B
        # `client_entry_node_socket` is the client's entry node socket (i.e. connection between client and entry node)
        client_entry_node_socket = self.connect_to_entry_node(entry_node)
        public_key_B = self.receive_data_from_entry_node(client_entry_node_socket)

        # Construct symmetric key 
        shared_key = private_key_a.exchange(public_key_B)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return derived_key

    def exhange_DH_middle_node(self, entry_node, entry_symmetric_key, middle_node):
        # Generate parameters (g, p)
        parameters = dh.generate_parameters(generator=2, key_size=2048)

        # Generate c and C
        private_key_c = parameters.generate_private_key()
        public_key_C = private_key_c.public_key()

        # Send C (encrypted with entry_symmetric_key) and parameters
        entry_addr, entry_left_port, entry_right_port = entry_node
        middle_addr, middle_left_port, middle_right_port = middle_node

        # parameters is an object. TODO: find out if this object can be sent correctly
        # Send from middle node's left port to entry node's right port
        message = [public_key_C, IS_CIRCUIT_SETUP, (entry_addr, entry_right_port), parameters] 
        fernet_cipher = Fernet(entry_symmetric_key)
        encrypted_message = [fernet_cipher.encrypt(pickle.dumps(x)) for x in message]
        encrypted_message.extend([pickle.dumps(IS_CIRCUIT_SETUP), pickle.dumps((middle_addr, middle_left_port))])
        self.send_message(encrypted_message, (entry_addr, entry_left_port))

        # Receive D
        # `client_entry_node_socket` is the client's entry node socket (i.e. connection between client and entry node)
        client_entry_node_socket = self.connect_to_entry_node(entry_node)
        public_key_D = self.receive_data_from_middle_via_entry_node(client_entry_node_socket, fernet_cipher)

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
        # generate parameters (g, p)
        parameters = dh.generate_parameters(generator=2, key_size=2048)

        # Generate e and E
        private_key_e = parameters.generate_private_key()
        public_key_E = private_key_e.public_key()

        # Send E (encrypted with entry_symmetric_key) and parameters
        fernet_cipher_entry = Fernet(entry_symmetric_key)
        fernet_cipher_middle = Fernet(middle_symmetric_key)

        exit_addr, exit_left_port, exit_right_port = exit_node
        middle_addr, middle_left_port, middle_right_port = middle_node
        entry_addr, entry_left_port, entry_right_port = entry_node

        #[public_key_E, IS_CIRCUIT_SETUP, middle_return_address, parameters]; Return to middle node's right port
        encrypted_message = [public_key_E, IS_CIRCUIT_SETUP, (middle_addr, middle_right_port), parameters]

        #[middle_key(public_key_E), middle_key(IS_CIRCUIT_SETUP), middle_key(exit_node_addr), middle_key(parameters)]
        # This is an intermediary message 
        encrypted_message = [fernet_cipher_middle.encrypt(pickle.dumps(x)) for x in encrypted_message] 

        #[middle_key(public_key_E), middle_key(IS_CIRCUIT_SETUP), middle_key(exit_node_addr),middle_key(parameters),IS_CIRCUIT_SETUP, middle_node_addr]
        encrypted_message.extend([pickle.dumps(IS_CIRCUIT_SETUP), pickle.dumps((middle_addr, middle_left_port))]) 

        #[entry_key(middle_key(public_key_E)), entry_key(middle_key(IS_CIRCUIT_SETUP)), entry_key(middle_key(exit_node_addr)), entry_key(IS_CIRCUIT_SETUP), entry_key(middle_node_addr)]
        encrypted_message = [fernet_cipher_entry.encrypt(pickle.dumps(x)) for x in encrypted_message]

        self.send_message(encrypted_message, (entry_addr, entry_left_port))

        # Receive F
        # `client_entry_node_socket` is the client's entry node socket (i.e. connection between client and entry node)
        client_entry_node_socket = self.connect_to_entry_node(entry_node)
        public_key_F = self.receive_data_from_exit_via_entry_node(client_entry_node_socket, fernet_cipher_entry, fernet_cipher_middle)

        # Construct symmetric key 
        shared_key = private_key_e.exchange(public_key_F)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        return derived_key
    
    def connect_to_entry_node(self, entry_node):
        """Connect to the entry node."""
        entry_addr, entry_left_port, entry_right_port = entry_node
        sending_address = (entry_addr, entry_left_port) #entry node's left port
        try:
            entry_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            entry_socket.connect(sending_address)
        except socket.error as e:
            print(f"Error connecting to directory server: {e}")
        return entry_socket


    def receive_data_from_entry_node(self, entry_socket):
        data = entry_socket.recv(4096)    # TODO: add a while loop for large amoutns of data, since we are assuming here currently that data is within 4096 bytes 
        entry_socket.close() 
        return pickle.loads(data)

    def receive_data_from_middle_via_entry_node(self, entry_socket, entry_symmetric_cipher):
        """Receives data sent by middle node to entry node"""
        data = entry_socket.recv(4096)
        entry_socket.close() 
        return entry_symmetric_cipher.decrypt(pickle.loads(data))

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
        #entry = [entry_addr, entry_left_port, entry_right_port]
        return entry, middle, exit 
        
   
        
    def layer_onion(self, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key, message, destination_server):
        cipher1 = Fernet(entry_symmetric_key)
        cipher2 = Fernet(middle_symmetric_key)
        cipher3 = Fernet(exit_symmetric_key)

        encrypted_message = [message, destination_server]

        encrypted_message = [cipher3.encrypt(pickle.dumps(x)) for x in encrypted_message]

        encrypted_message.append(pickle.dumps(exit[0]))

        encrypted_message = [cipher2.encrypt(x) for x in encrypted_message]

        encrypted_message.append(pickle.dumps(middle[0]))
        # Third encryption
        encrypted_message = [cipher1.encrypt(x) for x in encrypted_message]
        
        ## send this to entry node. 
        return encrypted_message
        
    
    def unlayer_onion(self, message, entry_symmetric_key, middle_symmetric_key, exit_symmetric_key):
        cipher1 = Fernet(entry_symmetric_key)
        cipher2 = Fernet(middle_symmetric_key)
        cipher3 = Fernet(exit_symmetric_key)

        decrypt_entry_layer = [cipher1.decrypt(x) for x in message]

        decrypt_middle_layer = [cipher2.decrypt(x) for x in decrypt_entry_layer[0]]

        decrypt_exit_layer = [cipher3.decrypt(x) for x in decrypt_middle_layer[0]]
        decrypted_message = pickle.loads(decrypt_exit_layer[0])
        return decrypted_message
