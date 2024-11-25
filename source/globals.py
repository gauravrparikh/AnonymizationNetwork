DS_ADDR = '127.0.0.1'
DS_CLIENT_PORT = 60006
DS_NODE_PORT = 60007
DESTINATION_PORT = 59993
RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048
NUM_NODES = 10
NUM_NODES_IN_CIRCUIT = 3
IS_CIRCUIT_SETUP = "is_circuit_setup"

IS_LOGGING = True

def LOG(message):
    if (IS_LOGGING):
        print(message)