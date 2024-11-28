from enum import Enum

class Message:
    """
    Class to construct messages to pass over sockets. 
        types: data_message, setup_message
    """
    
    def __init__(self, payload, forward_to,type):
        """Payload can be a list or a Message"""
        self.payload: str = payload
        self.forward_to: tuple = forward_to
        self.type: Message.MessageType = type
        
    def get_payload(self):
        return self.payload
    
    def get_forward_to(self):
        return self.forward_to
    
    def get_type(self):
        return self.type

class MessageType(Enum):
    SETUP = "setup_message"
    RETURN = "return_message"
    FORWARD = "forward_message"
    SERVER = "server_message"