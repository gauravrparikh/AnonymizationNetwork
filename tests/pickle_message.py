import pickle
class Message:
    """
    Class to construct messages to pass over sockets. 
        types: data_message, setup_message
    """
    
    def __init__(self, payload, forward_to,type):
        self.payload = payload
        self.forward_to = forward_to
        self.type = type
        
    def get_payload(self):
        return self.payload
    
    def get_forward_to(self):
        return self.forward_to
    
    def get_type(self):
        return self.type
    

Message1 = Message(payload=b'Hello', forward_to=('str',110), type='data_message')
pickle_Message1 = pickle.dumps(Message1)

Message2=pickle.loads(pickle_Message1)

print(Message1.get_payload() == Message2.get_payload())