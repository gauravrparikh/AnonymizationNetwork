import typing 
import socket
from node import Node
import random
import pickle
import threading
import globals

class DirectoryServer:
    def __init__(self,ds_addr=globals.DS_ADDR, client_port=globals.DS_CLIENT_PORT, node_port=globals.DS_NODE_PORT):
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
        # We assume that this will be enough to receive all the data.
        data = node_socket.recv(4096)

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
            listen_socket.listen(globals.NUM_NODES)
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

            # Logically not accurate
            listen_socket.listen(globals.NUM_NODES)
            print(f"Directory Server listening for clients on port {self.client_port}")
            while True:
                client_socket, address = listen_socket.accept()
                # Create a new thread for each client connection
                client_thread = threading.Thread(
                    target=self.handle_connection, args=((client_socket,))
                )
                client_thread.start()
                print(f"Started thread {client_thread.name} for client {address}")
    

    def handle_connection(self, client_socket):
        circuit = random.sample(list(self.node_keys.keys()), globals.NUM_NODES_IN_CIRCUIT)
        client_socket.sendall(pickle.dumps(circuit))
        print("Sent")


    def start(self,):
        threading.Thread(target=self.listen_for_nodes).start()
        threading.Thread(target=self.listen_for_clients).start()
    