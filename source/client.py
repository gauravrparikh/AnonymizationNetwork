import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import pickle
import globals

class Client:
    def __init__(self,  port=None, name="",addr="127.0.0.1"):
        self.port = port
        self.addr = addr
        self.name = name
        print("Client initialized.")
        # self.start()
        

    def __str__(self) -> str:
        return self.name
    

    def connect_to_directory_server(self, ds_address, ds_port):
        """Connect to the directory server and request a key."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ds_socket:
                print("HI")
                print(ds_address, ds_port)
                ds_socket.connect((ds_address, ds_port))
                ds_socket.sendall(pickle.dumps(self.name))
                print(f"Connected to directory server {ds_address}:{ds_port}")
                data = b'' + ds_socket.recv(4096)
                # while True: 
                #     curr = b''
                #     curr = ds_socket.recv(4096) # Receive a list of nodes from the directory server and a list of public keys. 
                #     data += curr
                #     print(f"Received from directory server: {pickle.load(data)}")
                #     if not curr:
                #         break
                # return data
                self.handle_directory_circuit_response(pickle.load(data))
        except socket.error as e:
            print(f"Error connecting to directory server: {e}")
            return None
        
        
    # def start(self,):
    #     """Start the client to listen for connections on the port."""
    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
    #         listen_socket.bind((self.addr, self.port))
    #         listen_socket.listen()
    #         print(f"Client listening on port {self.port}")
    #         while True:
    #             socket, address = listen_socket.accept()
    #             # Create a new thread for each client connection
    #             thread = threading.Thread(
    #                 target=self.handle_incoming, args=(socket, address)
    #             )
    #             thread.start()
    #             print(f"Started thread {thread.name} for client {address}")

    
    def handle_directory_circuit_response(self, data):
        """Given a list of nodes, build a circuit"""

        print(data)

        # self.node1 
        # self.node2
        # self.node3


    # def handle_server_response(self, socket, address):
    #     """Handle incoming connections and print received messages."""
    #     try:
    #         while True:
    #             data = socket.recv(4096)
    #             if not data:
    #                 print(f"Connection with {address} closed.")
    #                 break
    #             print(f"Received from {address}: {data.decode()}")
    #     except socket.error as e:
    #         print(f"Socket error with {address}: {e}")
    #     finally:
    #         left_socket.close()

    
    def connect_right(self, next_addr, next_port, message=b""):
        """Connect to the right neighbor and send a message."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as right_socket:
                right_socket.connect((next_addr, next_port))
                right_socket.sendall(message)
                print(f"Sent message to {next_addr}:{next_port}")
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
    public_exponent=globals.RSA_PUBLIC_EXPONENT,
    key_size=globals.RSA_KEY_SIZE,
)
public_key = private_key.public_key()