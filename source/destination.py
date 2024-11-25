import threading
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import pickle
import globals



class Destination:
    def __init__(self, left_port,  addr="127.0.0.1"):
        self.left_port = left_port
       
        self.addr = addr
        self.start()
        
    def start(self):
        """Start the node server to listen for connections on the left port."""
        #threading.Thread(self.broadcast_to_directory).start()

        threading.Thread(target=self.listen_for_clients).start()

  
    def listen_for_clients(self):
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
   

    def handle_left(self, left_socket, address):
        """Handle incoming connections"""
        try:
            data = b''
            while True:
                curr = left_socket.recv(4096)
                data += curr
                if not curr:
                    print(f"Connection with {address} closed.")
                    break
            print("Message Received", pickle.loads(pickle.loads(data)[0]))      
        except socket.error as e:
            print(f"Socket error with {address}: {e}")
        finally:
            left_socket.close()

    def connect_right(self, destination, message):
        """Connect to the right neighbor and send a message."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as right_socket:
                right_socket.connect(destination)
                right_socket.sendall(message)
                print(f"Sent message to {destination}")
        except socket.error as e:
            print(f"Error connecting ")

 

