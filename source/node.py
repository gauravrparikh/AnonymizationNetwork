import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pickle
from globals import LOG

class Node:
    def __init__(self, left_port,  right_port, directory_server_port, addr="127.0.0.1", directory_server_addr = globals.directory_server_addr):
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
        LOG("Starting Node")
        self.broadcast_to_directory()
        threading.Thread(target=self.listen_to_left).start()
        threading.Thread(target=self.listen_to_right).start()

    def start(self):
        """Start the node server to listen for connections on the left port."""
        #threading.Thread(self.broadcast_to_directory).start()
        self.broadcast_to_directory()
        threading.Thread(target=self.listen_for_clients).start()

    def broadcast_to_directory(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as directory_socket:
            LOG("Broadcasting Node to Directory")
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
            LOG(f"Listening on port {port}...")
            while True:
                client_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                client_thread = threading.Thread(
                    target=handler, args=(client_socket, address)
                )
                client_thread.start()
                LOG(f"Started thread {client_thread.name} for client {address}")
                         

    def delayer_onion(self, message):     
        message = pickle.loads(message)
        message = [self.cipher.decrypt(x) for x in  message]
        destination = pickle.loads(message.pop())
        self.connect_right(destination, pickle.dumps(message))

    def decrypt_message(self, message):
        fernet_cipher = Fernet(self.symmetric_key)
        return fernet_cipher.decrypt(message)
        
    
    def handle_left(self, left_socket, address):
        """Handle incoming connections"""
        left_data=self.get_data_from_left(left_socket, address) # get the data from left

        message = pickle.loads(left_data)
        if (globals.IS_CIRCUIT_SETUP in message): # if this is a diffie helman setup
            # if this is a diffie helman setup for current node
            if (len(message)==4):
                print("Received public key")
                public_key_B = self.do_primary_diffie_helman(message) #g^b, diffie helman for me (current node)
                # return g^b to the client by sending it leftward so that the client can construct g^ab (symmetric key) cuz client has g^a curently
                self.send_message_with_encryption(self.return_location, public_key_B)
            else:
            # if this is a diffie helman setup for a future node
                # decrypt the message with the symmetric key of the node
                message = [pickle.loads(self.decrypt_message(x)) for x in message]
                forward_location,forward_message = message[-1],message[:-2]    
                # pass on the message to the next node  
                self.send_message(forward_location, forward_message)
                
        else:
            # if this is a data message.
            #  
            
            # unlayer, unencrypt with the symmetric key and pass on the message to the next node 
            return message[0], False, message[2] 

    def do_primary_diffie_helman(self, message):
        recd_public_key,self.parameters = message[0],message[-1]
        private_key = self.parameters.generate_private_key()
        public_key = private_key.public_key() # send to left. B=g^b mod p
        shared_key = private_key.exchange(recd_public_key)
        self.symmetric_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_key)
        self.cipher = Fernet(self.symmetric_key)
        self.return_location=message[-2]
        return public_key  
        
    def get_data_from_left(self, left_socket, address,): 
        '''
        Get data from the left socket and return it to handle_left
        '''
        try:
            data = b''
            while True:
                curr = left_socket.recv(4096)
                data += curr
                if not curr:
                    print(f"Connection with {address} closed.")
                    break
        except socket.error as e:
            print(f"Socket error with {address}: {e}")
        finally:
            left_socket.close()
            return data
    
    # def get_data_from_right(self,right_socket, address):
    #     '''
    #     When we get data from right we have to layer it.
    #     '''
        
    #     try:
    #         data = b''
    #         while True:
    #             curr = right_socket.recv(4096)
    #             data += curr
    #             if not curr:
    #                 print(f"Connection with {address} closed.")
    #                 break
    #     except socket.error as e:
    #         print(f"Socket error with {address}: {e}")
    #     finally:
    #         right_socket.close()
    #         return data
    
            
    # def handle_right(self, right_socket, address):
    #     """Handle incoming connections"""
    #     try:
    #         data = b''
    #         while True:
    #             curr = right_socket.recv(4096)
    #             data += curr
    #             if not curr:
    #                 print(f"Connection with {address} closed.")
    #                 break
    #         self.unlayer_onion(data)
        
    #     except socket.error as e:
    #         print(f"Socket error with {address}: {e}")
    #     finally:
    #         right_socket.close()

    def send_message(self, destination_location, message):
        """Connect to the neighbor specified by destination and send a message."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as neighbor_socket:
                neighbor_socket.connect(destination_location)
                neighbor_socket.sendall(message)
                print(f"Sent message to {destination_location}")
        except socket.error as e:
            print(f"Error connecting ")
    
    def send_message_with_encryption(self, destination_location, message):
        """Connect to the left neighbor specified by destination and send a message."""
        encrypted_message = [self.cipher.encrypt(pickle.dumps(x)) for x in message]
        self.send_message(self, destination_location, encrypted_message)