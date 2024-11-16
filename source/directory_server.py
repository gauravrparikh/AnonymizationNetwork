import typing 
import socket
from node import Node
import random
import threading

class DirectoryServer:
    def __init__(self,nodes:list[(str,int)],ds_addr='',ds_port=60000):
        """
        nodes : str is the address of the node and int is the port of the node.
        """
        self.nodes = nodes
        self.ds_addr = ds_addr
        self.ds_port = ds_port
        self.node_keys = {} # Store the public keys of the nodes.
        self.start()
        
    def start(self,):
        """Start the directory server to listen for connections on the port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.ds_addr, self.ds_port))
            listen_socket.listen()
            print(f"Directory Server listening on port {self.ds_port}")
            while True:
                socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                thread = threading.Thread(
                    target=self.handle_connection, args=(socket, address)
                )
                thread.start()
                print(f"Started thread {thread.name} for client {address}")
    
       
    def return_path(self,):
        """
        return 3 random nodes from the list of nodes.
        """
        return random.sample(list(self.node_keys.keys()), 3)
        