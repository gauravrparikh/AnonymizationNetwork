from cryptography.fernet import Fernet

# Generate three keys
key1 = Fernet.generate_key()
key2 = Fernet.generate_key()
key3 = Fernet.generate_key()

cipher1 = Fernet(key1)
cipher2 = Fernet(key2)
cipher3 = Fernet(key3)

def encrypt_message(message):
    encrypted_message = [cipher3.encrypt(message.encode())]

    encrypted_message.append("Node 3 address".encode())

    encrypted_message = [cipher2.encrypt(x) for x in encrypted_message]

    encrypted_message.append("Node 2 address".encode())
    # Third encryption
    encrypted_message = [cipher1.encrypt(x) for x in encrypted_message]
    return encrypted_message

def decrypt_message(encrypted_message):
    # First decryption
    print(encrypted_message)
    decrypted_message = [cipher1.decrypt(x) for x in encrypted_message]
    print(decrypted_message)
    print(decrypted_message.pop().decode())
    # Second decryption
    decrypted_message = [cipher2.decrypt(x) for x in decrypted_message]
    print(decrypted_message)
    print(decrypted_message.pop().decode())
    # Third decryption
    decrypted_message = [cipher3.decrypt(x).decode() for x in decrypted_message]
    return decrypted_message
if __name__ == "__main__":
    message = "Destination Address"
    encrypted_message = encrypt_message(message)
    #print(f"Encrypted message: {encrypted_message}")

    decrypted_message = decrypt_message(encrypted_message)
    print(f"Decrypted message: {decrypted_message}")