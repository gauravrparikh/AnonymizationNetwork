import socket
import threading
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
                socket1.sendall(b"This is a long message, it is longer than the longest message I could type but I couldnt think of a longer sentence to write so I asked CHATGPT to generate a long sentence for me but it said it was too busy to help me out so I had to write this long sentence myself and I no longer have any idea what I am typing. This is a very long message intended to test the handling of large data packets within the network. The purpose of this message is to ensure that the system can manage and relay extensive information without any loss or corruption of data. This message continues to extend further, incorporating more words and phrases to increase its length significantly. By doing so, we can observe the behavior of the nodes and the efficiency of the relay mechanism. The message must be long enough to thoroughly test the system's capabilities and identify any potential issues that may arise when dealing with substantial amounts of data. This is crucial for the robustness and reliability of the network, as it must be able to handle various sizes of messages seamlessly. The end goal is to confirm that the system performs optimally under different conditions, including the transmission of lengthy messages like this one.")
                print("Message sent to node1")
        except Exception as e:
            print(f"Error in connection to node1: {e}")

    threading.Thread(target=connect_to_node1).start()

    # Initialize and start node2
    node2 = Node(40002, 40003)
    threading.Thread(target=node2.start).start()

# Start the main function in a separate thread
threading.Thread(target=main).start()

if __name__ == "__main__":
    message="This is a long message, it is longer than the longest message I could type but I couldnt think of a longer sentence to write so I asked CHATGPT to generate a long sentence for me but it said it was too busy to help me out so I had to write this long sentence myself and I no longer have any idea what I am typing. This is a very long message intended to test the handling of large data packets within the network. The purpose of this message is to ensure that the system can manage and relay extensive information without any loss or corruption of data. This message continues to extend further, incorporating more words and phrases to increase its length significantly. By doing so, we can observe the behavior of the nodes and the efficiency of the relay mechanism. The message must be long enough to thoroughly test the system's capabilities and identify any potential issues that may arise when dealing with substantial amounts of data. This is crucial for the robustness and reliability of the network, as it must be able to handle various sizes of messages seamlessly. The end goal is to confirm that the system performs optimally under different conditions, including the transmission of lengthy messages like this one."
    main(message)