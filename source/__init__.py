from node import Node
import socket 
import threading
from directory_server import DirectoryServer
from client import Client
import globals

global listen_count 

# Main function
def main():
    directory_server = DirectoryServer(globals.DS_ADDR, globals.DS_CLIENT_PORT, globals.DS_NODE_PORT)
    nodes = []
    port = 40000

    # Create nodes
    for i in range(5):
        node = Node(port, port + 1, globals.DS_NODE_PORT)
        nodes.append(node)
        port += 2
    for node in nodes:
        node.start()
    print("All nodes started")
    directory_server.check_nodes()

    # Create client
    client = Client()


if __name__ == "__main__":
    main()