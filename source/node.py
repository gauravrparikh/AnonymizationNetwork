import socket
import ssl
from enum import Enum
import threading
import queue


'''

Each node has a set of ports that it has to listen on and the set of ports it has to pass on the message  
It maintains a table that links which port is communicating to which other port. 

Each connection is called a circuit. 


Node 1:
    Receive message from client 
    decrypt_message(PrivateKey of Node1, message)-> address to Node 2
    send_message()-> Node 2
    receive_message()-> Node 2
    sender_address=store_sender_address()
    Manage Ports and sockets :
        Manage port linkages :
         Store the address of sender and reciver as tuple 


    Port A.1, Port A.2 <-> Port B.1, Port B.2
    if I receive on A then a relay to B 
    if I receive on B then I encrypt and send to A



        
Node 2:
    Receive message from node1
    decrypt_message(PrivateKey of Node1, message)-> address to Node 2
    send_message()-> Node 2


Node 3:
    Receive message from node2
    decrypt_message(PrivateKey of Node1, message)-> address to Node 2
    send_message()-> Node 3
    receive_message()-> Node 

Amazon:
    Receives message from Node 3
    sender address = store_sender_address()
    return information to the sender address. 
    


'''
