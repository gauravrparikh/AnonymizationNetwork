import fire
from node import Node
import socket 
import threading
from directory_server import DirectoryServer

global listen_count 
# Main function
def main():
    directory_server = DirectoryServer(ds_addr='127.0.0.1',client_port=60000, node_port=60001)
    nodes = []
    port = 40000
    for i in range(5):
        node = Node(port, port + 1, 60001)
        nodes.append(node)
        port += 2
    for node in nodes:
        node.start()
    print("All nodes started")
    directory_server.check_nodes()
if __name__ == "__main__":
    main()