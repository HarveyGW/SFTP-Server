import socket
import os
import sys
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Load parameters and key generation functions
def load_parameters(param_bytes):
    return serialization.load_pem_parameters(param_bytes, backend=default_backend())

def generate_private_key(params):
    return params.generate_private_key()

def generate_public_key(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Derive shared key function
def derive_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_bytes, backend=default_backend()
    )
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(shared_key)

def create_encryptor_decryptor(shared_key, iv=None):
    if iv is None:
        iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    return encryptor, decryptor, iv

# Upload handler function
def handle_upload(client_socket, shared_key, filename):
    # Create a file path for the file to be uploaded
    file_path = os.path.join(".", filename)

    # Initialize AES cipher with shared_key and a random IV
    aes_cipher = Cipher(algorithms.AES(shared_key), modes.CBC(os.urandom(16)), backend=default_backend())
    encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    # Open the file and send the encrypted data to the server
    with open(file_path, "rb") as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            padded_data = padder.update(data)
            encrypted_data = encryptor.update(padded_data)
            client_socket.sendall(encrypted_data)
        client_socket.sendall(encryptor.update(padder.finalize()))
        client_socket.sendall(encryptor.finalize())

    print(f"File '{filename}' uploaded successfully.")

# Download handler function
def handle_download(client_socket, shared_key, filename):
    # Create a file path for the downloaded file
    file_path = os.path.join("uploads", filename)

    # Initialize AES cipher with shared_key and a random IV
    aes_cipher = Cipher(algorithms.AES(shared_key), modes.CBC(os.urandom(16)), backend=default_backend())
    decryptor = aes_cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    # Open the file and write the decrypted data to it
    with open(file_path, "wb") as f:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            decrypted_data = decryptor.update(data)
            unpadded_data = unpadder.update(decrypted_data)
            f.write(unpadded_data)
            f.write(unpadder.update(decryptor.finalize()))

        print(f"File '{filename}' downloaded successfully.")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 12345))

server_param_bytes = client.recv(4096)
params = load_parameters(server_param_bytes)

client_private_key = generate_private_key(params)
client_public_key = generate_public_key(client_private_key)

# Receive the server's public key
server_public_key = client.recv(4096)

# Send the client's public key
client.sendall(client_public_key)

shared_key = derive_shared_key(client_private_key, server_public_key)
# Print the shared key information
print("Shared key:", shared_key.hex())
print("Key size:", len(shared_key) * 8, "bits")

while True:
    command = input("Enter your command (DOWNLOAD/UPLOAD): ")
    if command.upper() == "DOWNLOAD":
        filename = input("Enter the filename to download: ")

        encryptor, decryptor, iv = create_encryptor_decryptor(shared_key)
        padder = padding.PKCS7(128).padder()
        padded_request = padder.update(f"DOWNLOAD:{filename}".encode("latin-1")) + padder.finalize()
        encrypted_request = iv + encryptor.update(padded_request) + encryptor.finalize()
        client.sendall(encrypted_request)

        handle_download(client, shared_key, filename)
    elif command.upper() == "UPLOAD":
        filename = input("Enter the filename to upload: ")

        encryptor, decryptor, iv = create_encryptor_decryptor(shared_key)
        padder = padding.PKCS7(128).padder()
        print(padder)
        padded_request = padder.update(f"UPLOAD:{filename}".encode("latin-1")) + padder.finalize()
        encrypted_request = iv + encryptor.update(padded_request) + encryptor.finalize()
        client.sendall(encrypted_request)

        handle_upload(client, shared_key, filename)
    else:
        print("Invalid command. Please enter DOWNLOAD or UPLOAD.")

client.close()



