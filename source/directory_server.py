import typing 
import socket
from node import Node
import random
import pickle
import threading

class DirectoryServer:
    def __init__(self,ds_addr='127.0.0.1',client_port=60000, node_port=60001):
        """
        nodes : str is the address of the node and int is the port of the node.
        """
        self.nodes = []
        self.ds_addr = ds_addr
        self.client_port = client_port
        self.node_port = node_port
        self.node_keys = {} # Store the public keys of the nodes.
        self.start()
    
    def check_nodes(self):
        print(self.nodes)
        print(self.node_keys.items())
    def add_node(self, node_socket):
        """Handle incoming connections and print received messages."""
        data = node_socket.recv(4096)
        #We assume that this will be enough to receive all the data.
        
        # try:
        #     data = b''
        #     while True:
        #         data += node_socket.recv(4096)
        #         if not data:
        #             print(f"Connection closed.")
        #             break
        # except socket.error as e:
        #     print(f"Socket error with {e}")
        # finally:
        #     node_socket.close()
        print("Data", pickle.loads(data))
        node_addr, node_port, public_key = pickle.loads(data)
        self.nodes.append((node_addr, node_port))
        self.node_keys[(node_addr, node_port)] = public_key
        node_socket.close()
        
    def get_addr_port(self,):
        return self.ds_addr, self.client_port
    
    
    def listen_for_nodes(self,):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.ds_addr, self.node_port))
            listen_socket.listen(10)
            print(f"Directory Server listening for nodes on port {self.node_port}")
            while True:
                node_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                node_thread = threading.Thread(
                    target=self.add_node, args=((node_socket,))
                )
                node_thread.start()
                print(f"Started thread {node_thread.name} for node {address}")
    
    def listen_for_clients(self,):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_socket:
            listen_socket.bind((self.ds_addr, self.client_port))
            listen_socket.listen()
            print(f"Directory Server listening for clients on port {self.client_port}")
            while True:
                client_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                client_thread = threading.Thread(
                    target=self.handle_connection, args=(client_socket, address)
                )
                client_thread.start()
                print(f"Started thread {client_thread.name} for client {address}")
    def start(self,):
        threading.Thread(target=self.listen_for_nodes).start()
        threading.Thread(target=self.listen_for_clients).start()
        
    
       
    def return_path(self,):
        """
        return 3 random nodes from the list of nodes.
        """
        return random.sample(list(self.node_keys.keys()), 3)
        