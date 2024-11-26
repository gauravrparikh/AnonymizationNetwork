import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_der_public_key,load_der_parameters,Encoding, PublicFormat, ParameterFormat
import base64
import pickle
import globals
class Node:
    def __init__(self, left_port,  right_port, directory_server_port, addr="127.0.0.1", directory_server_addr = globals.DS_ADDR):
        self.my_left_port = left_port
        self.my_right_port = right_port
        self.my_addr = addr
        self.directory_server_addr = directory_server_addr
        self.directory_server_port = directory_server_port
        self.symmetric_key = None 
        self.cipher = None
        self.parameters = None
        self.return_location = None # this is a tuple of address and port of the prior node or client 
    

    def start(self):
        """Start the node server to listen for connections on the left port and right port."""
        globals.LOG("Starting Node")
        self.broadcast_to_directory()
        threading.Thread(target=self.listen, args=(self.my_left_port,self.handle_left)).start()
        threading.Thread(target=self.listen, args=(self.my_right_port,self.handle_right)).start()


    def broadcast_to_directory(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as directory_socket:
            globals.LOG("Broadcasting Node to Directory")
            directory_socket.connect((self.directory_server_addr, self.directory_server_port))
            directory_socket.sendall(pickle.dumps((self.my_addr, self.my_left_port, self.my_right_port))) # TODO : This is not right, add a public key here 


    def listen(self, port, handler):
        """
        Listens for incoming connections on the specified port and handles them using the specified handler.

        :param port: The port number to listen on.
        :param handler: The handler function to call for each accepted connection.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.my_addr, port))
            listen_socket.listen()
            globals.LOG(f"Listening on port {port}...")
            while True:
                client_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                client_thread = threading.Thread(
                    target=handler, args=(client_socket, address)
                )
                client_thread.start()
                globals.LOG(f"Started thread {client_thread.name} for client {address}")
            

    def handle_left(self, left_socket, address):
        """Handle connections coming to my left port"""
        globals.LOG("Handling incoming data from left")
        left_data = self.get_data(left_socket, address) # get the data from left
        message = pickle.loads(left_data) # unpickle data so we can analyse it + decide what to do; unpickling it makes it a list of things that have been encrypt(pickle(item)) or pickle(item)
        
        is_nested = any(isinstance(item, list) for item in message)
        print("HMM", message)

        if is_nested:   # Decryption necessary
            # This is not the final node, keep passing it on
            inner_message, outer_message = message
            outer_message = [pickle.loads(self.decrypt_message(x)) for x in outer_message]
            inner_message = [pickle.loads(self.decrypt_message(x)) for x in inner_message]

            print("OUTER ", outer_message)
            print("INNER ", inner_message)

            if (outer_message[0] == globals.IS_CIRCUIT_SETUP):
                globals.LOG("Setting up Diffie-Hellman for future node")
                message = [pickle.loads(self.decrypt_message(y)) for x in message for y in x]
                forward_location, forward_message = outer_message[1], inner_message    
                
                forward_message = [pickle.dumps(x) for x in forward_message]
                self.send_message(forward_location, pickle.dumps(forward_message))
            else: 
                globals.LOG(f"Received data message from {address}")
                self.send_message_with_encryption(outer_message[1], inner_message)

        else:   # This is the final node in the sending process; Decryption not necessary
            # Assign individual values in message
            unpickled_message = [pickle.loads(x) for x in message]
            client_public_key, parameters, circuit_flag, client_return_address = unpickled_message

            if (circuit_flag == globals.IS_CIRCUIT_SETUP):
                # Do Diffie-Hellman for current node
                globals.LOG("Is a circuit setup process; doing Diffie-Hellman")
                print("doing DH ", unpickled_message)
                public_key_B = self.do_primary_diffie_hellman(unpickled_message)
                print("Key size:", public_key_B.key_size)
                self.send_message(self.return_location, pickle.dumps([public_key_B.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)]))
                # TODO: THE KEY BEING SENT BACK IS NOT GETTING RECOGNIZED?? IDK WHY

        # try:
        #     if (globals.IS_CIRCUIT_SETUP == pickle.loads(message[-2])):
        #         # if this is a Diffie-Helman setup for current node
        #         globals.LOG("Is a circuit setup process")
        #         if (len(message)==4):
        #             message = [pickle.loads(x) for x in message]
        #             globals.LOG(f"Received Diffie-Hellman setup message from {address}")
        #             public_key_B = self.do_primary_diffie_helman(message) #g^b, diffie helman for me (current node)
        #             # return g^b to the client by sending it leftward so that the client can construct g^ab (symmetric key) cuz client has g^a curently
        #             self.send_message(self.return_location, pickle.dumps([public_key_B.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)]))
        # except Exception as e:
        # # if this is a Diffie-Helman setup for a future node OR this is a data message 
        #     # decrypt the message with the symmetric key of the node and pass on the remaining to the right
        #     if len(message)>2:
        #         globals.LOG("Setting up DH for future node")
        #         # globals.LOG(f"Message {message}")
        #         message = [pickle.loads(self.decrypt_message(x)) for x in message]
        #         # forward_message is a list
        #         forward_location, forward_message = message[-1], message[:-2]    
        #         # pass on the message to the next node  
        #         globals.LOG(f"Forward message {forward_message}")

        #         forward_message = [pickle.dumps(x) for x in forward_message]
        #         self.send_message_with_encryption(forward_location, forward_message)
        #     else:
        #         # this is a data message to the exit node, decrypt and send to the origin server.
        #         globals.LOG(f"Received message from {address}")
        #         globals.LOG(f"Message: {message}")
        #         self.send_message_with_encryption(message[1],message[0])
        #         # pass on the message to the next node
               

    def handle_right(self, right_socket, address):
        """Handle connections coming to my right port"""
        right_data=self.get_data(right_socket, address) # get the data from right
        message = pickle.loads(right_data)
        message = [pickle.dumps(x) for x in message]
        self.send_message_with_encryption(self.return_location, message) # send the message to the left
        

    def decrypt_message(self, message):
        globals.LOG(f"Symmetric Key: {self.symmetric_key}")
        fernet_cipher = Fernet(base64.urlsafe_b64encode(self.symmetric_key))
        return fernet_cipher.decrypt(message)

        
    def do_primary_diffie_hellman(self, message):
        self.return_location, recd_public_key, self.parameters = message[-1], load_der_public_key(message[0]), load_der_parameters(message[1])
        globals.LOG(f"return location:{self.return_location}")
        private_key = self.parameters.generate_private_key()
        public_key = private_key.public_key() # send to left. B=g^b mod p
        shared_key = private_key.exchange(recd_public_key)
        globals.LOG(f"Shared key: {shared_key}")
        self.symmetric_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_key)
        self.cipher = Fernet(base64.urlsafe_b64encode(self.symmetric_key))
        return public_key  
        
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
    
    
    def send_message(self, destination_location, message):
        """Connect to the neighbor specified by destination and send a message."""
        # globals.LOG(f"Encrypted message: {message}")
        globals.LOG(f'Sending encrypted message to {destination_location}')
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as neighbor_socket:
                neighbor_socket.connect(destination_location)
                neighbor_socket.sendall(message)
                # globals.LOG(f"Message: {message}, sent to {destination_location}")
        except socket.error as e:
            globals.LOG(f"Error connecting {e}")
    
    def send_message_with_encryption(self, destination_location, message):
        """Connect to the left neighbor specified by destination and send a message."""
        encrypted_message = [self.cipher.encrypt(x) for x in message]
        encrypted_message = pickle.dumps(encrypted_message)
        globals.LOG(f'Sending encrypted message to {destination_location}')
        self.send_message(destination_location, encrypted_message)