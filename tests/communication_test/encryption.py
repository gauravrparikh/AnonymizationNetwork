from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate three different RSA key pairs
key_pair_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key_pair_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key_pair_3 = rsa.generate_private_key(public_exponent=65537, key_size=2048)

public_key_1 = key_pair_1.public_key()
public_key_2 = key_pair_2.public_key()
public_key_3 = key_pair_3.public_key()

# Encrypt function (single encryption using the given public key)
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Decrypt function (single decryption using the given private key)
def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

# Example message
message = "Hello, this is a secret message."

# Convert message to bytes
message_bytes = message.encode("utf-8")

# Encrypt the message three times with three different keys
encrypted_message = encrypt_message(public_key_1, message_bytes)
print(f"Encrypted message (after 1 layer): {encrypted_message}")
encrypted_message = encrypt_message(public_key_2, encrypted_message)
print(f"Encrypted message (after 2 layers): {encrypted_message}")
encrypted_message = encrypt_message(public_key_3, encrypted_message)
print(f"Encrypted message (after 3 layers): {encrypted_message}")

# # Decrypt the message three times in reverse order
# decrypted_message = decrypt_message(key_pair_3, encrypted_message)
# decrypted_message = decrypt_message(key_pair_2, decrypted_message)
# decrypted_message = decrypt_message(key_pair_1, decrypted_message)
# decrypted_message = decrypted_message.decode("utf-8")
# print(f"Decrypted message (after 3 layers): {decrypted_message}")
