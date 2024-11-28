class Message:
    """
    Class to construct messages to pass over sockets. 
        types: data_message, setup_message
    """
    
    def __init__(self, payload, forward_to,type):
        """Payload can be a list or a Message"""
        self.payload = payload
        self.forward_to = forward_to
        self.type = type
        
    def get_payload(self):
        return self.payload
    
    def get_forward_to(self):
        return self.forward_to
    
    def get_type(self):
        return self.type
    
    