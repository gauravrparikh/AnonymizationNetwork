import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import pickle

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
    def __init__(self, left_port,  right_port, ds_port, addr="127.0.0.1", ds_addr = "127.0.0.1"):
        self.left_port = left_port
        self.right_port = right_port
        self.addr = addr
        self.ds_addr = ds_addr
        self.ds_port = ds_port
        #print("Node initialized.")

    def broadcast_to_directory(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as directory_socket:
            symmetric_key = self.generate_key()
            print((self.ds_addr, self.ds_port))
            directory_socket.connect((self.ds_addr, self.ds_port))
            directory_socket.sendall(pickle.dumps((self.left_port, self.addr, symmetric_key)))
            
    
    def listen_for_clients(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.addr, self.left_port))
            listen_socket.listen()
            print(f"Node listening on port {self.left_port}")
            while True:
                left_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                left_thread = threading.Thread(
                    target=self.handle_left, args=(left_socket, address)
                )
                left_thread.start()
                #print(f"Started thread {left_thread.name} for client {address}")
    def start(self):
        """Start the node server to listen for connections on the left port."""
        #threading.Thread(self.broadcast_to_directory).start()
        self.broadcast_to_directory()
        threading.Thread(target=self.listen_for_clients).start()

    def handle_left(self, left_socket, address):
        """Handle incoming connections and print received messages."""
        try:
            while True:
                data = left_socket.recv(4096)
                if not data:
                    print(f"Connection with {address} closed.")
                    break
                #print(f"Received from {address}: {pickle.loads(data)}")
        except socket.error as e:
            print(f"Socket error with {address}: {e}")
        finally:
            left_socket.close()

    def connect_right(self, next_addr, next_port, message=b""):
        """Connect to the right neighbor and send a message."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as right_socket:
                right_socket.connect((next_addr, next_port))
                right_socket.sendall(message)
                #print(f"Sent message to {next_addr}:{next_port}")
        except socket.error as e:
            print(f"Error connecting to {next_addr}:{next_port} - {e}")

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

    def relay_messages(self, src_socket, dst_socket):
        """Relay messages from source socket to destination socket."""
        try:
            data=b''
            while True:
                data += src_socket.recv(4096)
                if not data:
                    break
                dst_socket.sendall(data)
        except socket.error as e:
            print(f"Error during message relay: {e}")
        finally:
            print("Relay complete.")

# Test key generation and encryption
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()



