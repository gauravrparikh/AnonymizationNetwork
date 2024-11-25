from cryptography.hazmat.primitives.asymmetric import dh
import pickle
import socket

parameters = dh.generate_parameters(generator=2, key_size=2048)
pickle.dumps(parameters)
def send_message(message, destination):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as right_socket:
            right_socket.connect(destination)
            right_socket.sendall(message)
            print(f"Sent message to {destination}")
    except socket.error as e:
        print(f"Error connecting ")
        
destination = ('127.0.0.1', 60007)
send_message(pickle.dumps(parameters), destination)