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


    def handle_browser(self, browser_socket: socket.socket):
        directory_socket = self.connect_to_directory_server()
        globals.LOG("Connected to directory server")

        # Each node is of the form (addr, left port, right port)
        entry, middle, exit = self.get_circuit(directory_socket) 

        # Generate symmetric keys with Diffie Hellman
        globals.LOG("Generating symmetric keys with Diffie Hellman")
        entry_symmetric_key = self.exchange_DH_entry_node(entry)
        middle_symmetric_key = self.exhange_DH_middle_node(entry, entry_symmetric_key, middle)
        exit_symmetric_key = self.exchange_DH_exit_node(entry, entry_symmetric_key, middle, middle_symmetric_key, exit)
        
        # Create two threads to relay messages bidirectionally

        #browser -> anon network (entry node)
        globals.LOG("Relaying messages bidirectionally")
        browser_to_anon_thread = threading.Thread(target=self.relay_messages_from_browser, 
                                                  args=(browser_socket, entry, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key,))
        #anon network (entry node) -> browser
        globals.LOG("Relaying messages bidirectionally")
        anon_to_browser_thread = threading.Thread(target=self.relay_messages_to_browser, args=(browser_socket,entry_symmetric_key, middle_symmetric_key, exit_symmetric_key))

        #start the threads
        globals.LOG("Starting threads")
        browser_to_anon_thread.start()
        anon_to_browser_thread.start()

        #wait for the threads to finish (to clean up sockets)
        globals.LOG("Waiting for threads to finish")
        browser_to_anon_thread.join()
        anon_to_browser_thread.join()

        #close the sockets
        browser_socket.close()
        directory_socket.close()
    

    def accept_browser_connection(self):
        """Accept browser connection and return browser socket and address"""
        # block until a browser connects to us.
        # Accepts a browser connection and returns tuple (connection object, addr of browser)
        globals.LOG("Waiting for browser connection")   
        return self.socket_to_browser.accept()
        
    
    def relay_messages_from_browser(self, browser_socket:socket.socket, entry, entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key):
        #returns when the source finishes sending data (empty byte string)
        globals.LOG("Relaying messages from browser")
        while True:
            data = browser_socket.recv(1024)
            globals.LOG("Data received from browser", data[:10])
            if not data:
                break            
            # Encrypt message with symmetric keys
            message = self.layer_onion(entry_symmetric_key, middle, middle_symmetric_key, exit, exit_symmetric_key, data,(globals.DESTINATION_ADDR, globals.DESTINATION_PORT) )
            # Send message to destination
            self.send_message(pickle.dumps(message), entry[0])

        browser_socket.shutdown(socket.SHUT_WR)
        

    def relay_messages_to_browser(self, browser_socket:socket.socket,entry_symmetric_key, middle_symmetric_key, exit_symmetric_key):
         #Get response from destination
        response = self.get_response_from_destination_server() # the destination server is the "source" here    
        globals.LOG("Response from destination server", response[:10])
        # Decrypt message with symmetric keys
        self.unlayer_onion(response, entry_symmetric_key, middle_symmetric_key, exit_symmetric_key)
        globals.LOG("Unlayered response from destination server", response[:10])
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
                    globals.LOG(f"Connection with {address} closed.")
                    break
            globals.LOG("Message Received", pickle.loads(data))    
            return pickle.loads(data)  
        except socket.error as e:
           globals.LOG(f"Socket error with {address}: {e}")
        finally:
            right_socket.close()        

    def exchange_DH_entry_node(self, entry_node):
        globals.LOG("############## Exchanging Diffie Hellman keys with entry node ##############")
        
        # Generate parameters and private key 
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key_a = parameters.generate_private_key()
        public_key_A = private_key_a.public_key()
        globals.LOG("Generated parameters and private key")
        
        # Establish addresses
        entry_addr, entry_left_port, _ = entry_node
        entry_receiving_address = (entry_addr, entry_left_port) # final destination in this function (client's right port sends to entry node's left port)
        client_return_address = (self.my_address, self.client_right_port) # forward back to ourselves (entry node's right port sends to client's right port)

        # Send parameters and public key; pickle every element in message, then pickle the entire list itself
        message = [public_key_A.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3), globals.IS_CIRCUIT_SETUP, client_return_address]
        message = [pickle.dumps(x) for x in message]
        self.send_message(pickle.dumps(message), entry_receiving_address) #TODO: encrypt with TLS
        globals.LOG("Sent message to entry node")

        # Receive entry node's public key (i.e. B)
        client_entry_node_socket, client_entry_address = self.listen_to_node(self.client_right_port)
        public_key_B = self.get_data(client_entry_node_socket, client_entry_address)
        public_key_B = pickle.loads(public_key_B)
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

        # Establish addresses
        entry_addr, entry_left_port, entry_right_port = entry_node
        middle_addr, middle_left_port, _ = middle_node
        entry_receiving_address = (entry_addr, entry_left_port)
        middle_receiving_address = (middle_addr, middle_left_port)
        middle_return_address = (entry_addr, entry_right_port)

        # Send parameters and public key from entry node's right port to middle node's left port; 
        # Encrypt the message being sent from entry to middle. Ensure to pickle each element then encrypt the entire list
        inner_message = [public_key_C.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), parameters.parameter_bytes(Encoding.DER, ParameterFormat.PKCS3), globals.IS_CIRCUIT_SETUP, middle_return_address]

        outer_message = [globals.IS_CIRCUIT_SETUP, middle_receiving_address]

        cipher = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        encrypted_message = [[cipher.encrypt(pickle.dumps(x)) for x in inner_message], [cipher.encrypt(pickle.dumps(x)) for x in outer_message]]

        # encrypted_message = [cipher.encrypt(pickle.dumps(x)) for x in message] # pickle each element

        print("AHH", encrypted_message)

        self.send_message(pickle.dumps(encrypted_message), entry_receiving_address)
        globals.LOG("Sent message to middle node")
        
        # Receive middle node's public key
        client_entry_node_socket, client_entry_address = self.listen_to_node(self.client_right_port)
        public_key_D = self.get_data(client_entry_node_socket, client_entry_address)

        public_key_D = pickle.loads(public_key_D)
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
        # generate parameters (g, p)
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        globals.LOG("Exchanging Diffie Hellman keys with exit node")
        # Generate e and E
        private_key_e = parameters.generate_private_key()
        public_key_E = private_key_e.public_key()
        globals.LOG("Sending message to exit node")
        # Send E (encrypted with entry_symmetric_key) and parameters
        fernet_cipher_entry = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        fernet_cipher_middle = Fernet(base64.urlsafe_b64encode(middle_symmetric_key))
        globals.LOG("Sending message to exit node")
        exit_addr, exit_left_port, exit_right_port = exit_node
        middle_addr, middle_left_port, middle_right_port = middle_node
        entry_addr, entry_left_port, entry_right_port = entry_node

        #[public_key_E, IS_CIRCUIT_SETUP, middle_return_address, parameters]; Return to middle node's right port
        encrypted_message = [public_key_E, parameters, globals.IS_CIRCUIT_SETUP, (middle_addr, middle_right_port)]
        globals.LOG("Sending message to exit node")
        #[middle_key(public_key_E), middle_key(IS_CIRCUIT_SETUP), middle_key(exit_node_addr), middle_key(parameters)]
        # This is an intermediary message 
        encrypted_message = [fernet_cipher_middle.encrypt(pickle.dumps(x)) for x in encrypted_message] 

        #[middle_key(public_key_E), middle_key(IS_CIRCUIT_SETUP), middle_key(exit_node_addr),middle_key(parameters),IS_CIRCUIT_SETUP, middle_node_addr]
        encrypted_message.extend([pickle.dumps(globals.IS_CIRCUIT_SETUP), pickle.dumps((middle_addr, middle_left_port))]) 
        globals.LOG("Sending message to exit node")
        #[entry_key(middle_key(public_key_E)), entry_key(middle_key(IS_CIRCUIT_SETUP)), entry_key(middle_key(exit_node_addr)), entry_key(IS_CIRCUIT_SETUP), entry_key(middle_node_addr)]
        encrypted_message = [fernet_cipher_entry.encrypt(pickle.dumps(x)) for x in encrypted_message]

        self.send_message(encrypted_message, (entry_addr, entry_left_port))
        globals.LOG("Sent message to exit node")    
        # Receive F
        # `client_entry_node_socket` is the client's entry node socket (i.e. connection between client and entry node)
        client_entry_node_socket = self.connect_to_entry_node(entry_node)
        public_key_F = self.receive_data_from_exit_via_entry_node(client_entry_node_socket, fernet_cipher_entry, fernet_cipher_middle)
        public_key_F = load_der_public_key(public_key_F)
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


    # def receive_data_from_entry_node(self, entry_socket, entry_address):
    #     data = self.get_data(entry_socket, entry_address)
    #     return pickle.loads(data)


    # def receive_data_from_middle_via_entry_node(self, entry_socket, entry_symmetric_cipher):
    #     """Receives data sent by middle node to entry node"""
    #     data = entry_socket.recv(4096)
    #     entry_socket.close() 
    #     return entry_symmetric_cipher.decrypt(pickle.loads(data))

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
        cipher1 = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        cipher2 = Fernet(base64.urlsafe_b64encode(middle_symmetric_key))
        cipher3 = Fernet(base64.urlsafe_b64encode(exit_symmetric_key))

        # message = [GET request, 152.3....]
        encrypted_message = [message, destination_server]
        
        # encrypted_message = [[encrypt(pickled(GET request)), encrypt(pickled(152.3...))]]
        encrypted_message = [[cipher3.encrypt(pickle.dumps(x)) for x in encrypted_message]]

        # encrypted_message = [[encrypt(pickled(GET request)), encrypt(pickled(152.3...))], pickle(exit's addr, exit's left port)]
        exit_left_addr = (exit[0], exit[1])
        encrypted_message.append(pickle.dumps(exit_left_addr))

        # encrypted_message = [[[encrypt w/ cipher 2 ([encrypt(pickled(GET request)), encrypt(pickled(152.3...))]), encrypt w/ cipher 2(pickle(exit's addr, exit's left port))]]
        # encrypted_message = [[[X], Y]]
        encrypted_message = [[cipher2.encrypt(x) for x in encrypted_message]]

        # encrypted_message = [[[X], Y], pickle(middle address, middle left port)]
        middle_left_addr = (middle[0], middle[1])
        encrypted_message.append(pickle.dumps(middle_left_addr))

        # encrypted_message = [encrypt([[X], Y]), encrypt(pickle(middle address, middle left port))]
        encrypted_message = [cipher1.encrypt(x) for x in encrypted_message]
        
        ## send this to entry node. 
        return encrypted_message
        
    
    def unlayer_onion(self, message, entry_symmetric_key, middle_symmetric_key, exit_symmetric_key):
        cipher1 = Fernet(base64.urlsafe_b64encode(entry_symmetric_key))
        cipher2 = Fernet(base64.urlsafe_b64encode(middle_symmetric_key))
        cipher3 = Fernet(base64.urlsafe_b64encode(exit_symmetric_key))

        decrypt_entry_layer = [cipher1.decrypt(x) for x in message]
        decrypt_middle_layer = [cipher2.decrypt(x) for x in decrypt_entry_layer[0]]
        decrypt_exit_layer = [cipher3.decrypt(x) for x in decrypt_middle_layer[0]]

        decrypted_message = pickle.loads(decrypt_exit_layer[0])
        return decrypted_message
