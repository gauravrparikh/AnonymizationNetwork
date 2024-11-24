import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pickle
import globals

'''

Each node has a set of ports that it has to listen on and the set of ports it has to pass on the message  
It maintains a table that links which left_port is communicating to which other left_port. 

Each connection is called a circuit. 


Node 1:
    Receive message from client 
    decrypt_message(PrivateKey of Node1, message)-> address to Node 2
    send_message()-> Node 2
    receive_message()-> Node 2
    sender_address=store_sender_address()
    Manage Ports and sockets :
        Manage left_port linkages :
         Store the address of sender and reciver as tuple 


    Port A.1, Port A.2 <-> Port B.1, Port B.2
    if I receive on A then a relay to B 
    if I receive on B then I encrypt and send to A



        
Node 2:
    Receive message from node1
    decrypt_message(PrivateKey of Node1, message)-> address to Node 2
    send_message()-> Node 2


Node 3:
    Receive message from node2
    decrypt_message(PrivateKey of Node1, message)-> address to Node 2
    send_message()-> Node 3
    receive_message()-> Node 

Amazon:
    Receives message from Node 3
    sender address = store_sender_address()
    return information to the sender address. 
    


'''


class Node:
    def __init__(self, left_port,  right_port, ds_port, addr="127.0.0.1", ds_addr = globals.DS_ADDR):
        self.left_port = left_port
        self.right_port = right_port
        self.addr = addr
        self.ds_addr = ds_addr
        self.ds_port = ds_port
        self.symmetric_key = None 
        self.cipher = None
        self.parameters = None
        self.return_location=None # this is a tuple of address and port of the prior node or client 
    
    def start(self):
        """Start the node server to listen for connections on the left port and right port."""
        #threading.Thread(self.broadcast_to_directory).start()
        self.broadcast_to_directory()
        threading.Thread(target=self.listen_to_left).start()
        threading.Thread(target=self.listen_to_right).start()

    def broadcast_to_directory(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as directory_socket:         
            directory_socket.connect((self.ds_addr, self.ds_port))
            directory_socket.sendall(pickle.dumps((self.addr, self.left_port, self.right_port))) # TODO : This is not right, add a public key here 
            
    def listen_to_left(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.addr, self.left_port))
            listen_socket.listen()
            while True:
                left_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                left_thread = threading.Thread(
                    target=self.handle_left, args=(left_socket, address)
                )
                left_thread.start()
                #print(f"Started thread {left_thread.name} for client {address}")
                
    def listen_to_right(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.addr, self.right_port))
            listen_socket.listen()
            while True:
                right_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                right_thread = threading.Thread(
                    target=self.handle_right, args=(right_socket, address) #TODO: handle right
                )
                right_thread.start()
                #print(f"Started thread {right_thread.name} for client {address}")
                
    def start(self):
        """Start the node server to listen for connections on the left port."""
        #threading.Thread(self.broadcast_to_directory).start()
        self.broadcast_to_directory()
        threading.Thread(target=self.listen_for_clients).start()

    def unlayer_onion(self, message):  
    
    # either the message is a public key or it has to be relayed 
    
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