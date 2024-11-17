import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import pickle
import globals

class Client:
    def __init__(self,  message, port=None,  name="",addr="127.0.0.1", ds_addr=globals.DS_ADDR, ds_port=globals.DS_CLIENT_PORT):
        self.port = port
        self.addr = addr
        self.name = name
        self.ds_addr = ds_addr
        self.ds_port = ds_port
        self.start_request(message)
        

    def __str__(self) -> str:
        return self.name
    

    def connect_to_directory_server(self,):
        """Connect to the directory server and request a key."""
        try:
            directory_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            directory_socket.connect((self.ds_addr, self.ds_port))
            directory_socket.sendall(pickle.dumps("Requesting circuit"))
        except socket.error as e:
            print(f"Error connecting to directory server: {e}")
        return directory_socket

    def start_request(self, message):
        """Start the node server to listen for connections on the left port."""
        directory_socket= self.connect_to_directory_server()
        #threading.Thread(target=self.listen_for_directory_path,args=((directory_socket,))).start()
        data = self.listen_for_directory_path(directory_socket) 

        entry, middle, exit = self.handle_directory_circuit_response(data)
        
        message = self.layer_onion(entry, middle, exit, message,("127.0.0.1", globals.DESTINATION_PORT) )
        self.send_message(pickle.dumps(message), entry[0])

    

    def send_message(self, message, destination):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as right_socket:
                right_socket.connect(destination)
                right_socket.sendall(message)
                print(f"Sent message to {destination}")
        except socket.error as e:
            print(f"Error connecting ")


        

    def listen_for_directory_path(self,directory_socket):
        """
        Listens for the response from the directory server which is a path of nodes.
        """
        data = directory_socket.recv(4096)    # assume data is within 4096 bytes
        directory_socket.close() 
        return data 
        
                
    def handle_directory_circuit_response(self, data):
        """Given a list of nodes, build a circuit"""
        entry, middle, exit=pickle.loads(data)
        

        #encrypt message 

        return entry,middle,exit
        # self.node1 
        # self.node2
        # self.node3
   
        
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

