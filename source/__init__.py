from node import Node
import socket 
import threading
from directory_server import DirectoryServer
from client import Client
from destination import Destination
import globals

# Main function
def main():
    directory_server = DirectoryServer(globals.DS_ADDR, globals.DS_CLIENT_PORT, globals.DS_NODE_PORT)
    nodes = []
    port = 40000
    browser_port=8889

    # Create nodes
    for i in range(3):
        node = Node(port, port + 1, globals.DS_NODE_PORT)
        nodes.append(node)
        port += 2
    for node in nodes:
        node.start()
   
    # Create client
    client = Client()




if __name__ == "__main__":
    main()