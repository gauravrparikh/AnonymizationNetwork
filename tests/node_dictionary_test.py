import random 
import socket 
import pickle
import sys
import os
import time
import threading 
import socket 
import sys
import os 
sys.path.append(os.path.abspath("../source"))
from node import Node



def main(message):
    # Initialize and start node1
    node1 = Node(40000, 40001)
    threading.Thread(target=node1.start).start()

    # Connect to node1 and send a message
    def connect_to_node1():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket1:
                socket1.connect(("127.0.0.1", 40000))
                socket1.sendall(message)
                print("Message sent to node1")
        except Exception as e:
            print(f"Error in connection to node1: {e}")

    threading.Thread(target=connect_to_node1).start()

    # Initialize and start node2
    node2 = Node(40002, 40003)
    threading.Thread(target=node2.start).start()

    # Start the main function in a separate thread
    
def dict_to_string(node_keys):
    return ",".join(f"{key}:{value}" for key, value in node_keys.items())


def string_to_dict(node_keys_str):
    return {
        key_value[0]: int(key_value[1]) 
        for key_value in (item.rsplit(":", 1) for item in node_keys_str.split(","))
    }


if __name__ == "__main__":
    node_keys = {'127.0.0.1:8899':1,'127.0.0.1:8891':8,'127.0.0.1:88911':6,'127.0.0.1:88919':11} # Store the public keys of the nodes.

    message=pickle.dumps(random.sample(list(node_keys.items()), 3)) # Pickle the message to send to the directory server.
    threading.Thread(target=main,args=((message,))).start()
    
    
