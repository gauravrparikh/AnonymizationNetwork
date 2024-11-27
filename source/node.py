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
from .message import Message
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
        message = pickle.loads(left_data) # unpickle data so we can analyse it + decide what to do; unpickling it makes it a Message Object
        if (self.cipher is None ):
            if (message.get_type() == "setup_message"):
                # if this is a Diffie-Helman setup for current node
                globals.LOG("Circuit setup process for current node")
                DH_message = message.get_payload()
                assert isinstance(DH_message, list)
                return_location = message.get_forward_to()
                globals.LOG(f"Received Diffie-Hellman setup message from {address}")
                public_key_B = self.do_primary_diffie_hellman(DH_message,return_location) #g^b, diffie hellman for me (current node)
                # return g^b to the client by sending it leftward so that the client can construct g^ab (symmetric key) cuz client has g^a curently
            
                DH_return_payload=[public_key_B.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)] # [key_B]
                message = pickle.dumps(Message(DH_return_payload, None, "return_message")) # Construct a return message with the payload being a list. 
                self.send_message(self.return_location, message)

        else:
        # if this is a Diffie-Helman setup for a future node OR this is a data message 
            # decrypt the message with the symmetric key of the current node and pass on the remaining to the right
            message = self.loads(self.cipher.decrypt(message))
            payload_message=message.get_payload()
            assert isinstance(payload_message, Message) # Forward the message to the right. 
            forward_location, forward_message = message.get_forward_to(), pickle.dumps(payload_message)
            self.send_message(forward_location, forward_message)
          



    def handle_right(self, right_socket, address):
        """Handle connections coming to my right port"""
        globals.LOG("Handling right")
        right_data=self.get_data(right_socket, address) # get the data from right
        message = pickle.loads(right_data)
        globals.LOG(f"Message @ right {message}")
        self.send_message_with_encryption(self.return_location, message) # send the message to the left
        

        
    def do_primary_diffie_hellman(self, DH_message, return_location):
        recd_public_key, self.parameters, self.return_location =  load_der_public_key(DH_message[0]), load_der_parameters(DH_message[1]),return_location
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
        encrypted_message = self.cipher.encrypt(message)
        encrypted_message = pickle.dumps(encrypted_message)
        globals.LOG(f'Sending encrypted message to {destination_location}')
        self.send_message(destination_location, encrypted_message)