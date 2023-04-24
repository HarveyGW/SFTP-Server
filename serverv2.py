import socket
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import re
from tqdm import tqdm
import time


# Key and parameter generation functions
def generate_parameters():
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

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


def handle_upload(client_socket, shared_key, filename):
    filename = re.sub(r'[^\x20-\x7E]+', '', filename)
    file_path = os.path.join("uploads", filename)

    size_data = client_socket.recv(4)
    file_size = int.from_bytes(size_data, byteorder='big')
    print(f"File Size: {file_size}")

    iv = client_socket.recv(16)
    _, decryptor, _ = create_encryptor_decryptor(shared_key, iv)

    with open(file_path, "wb") as f:
        bytes_received = 0
        while bytes_received < file_size:
            encrypted_data = client_socket.recv(min(file_size - bytes_received, 1024))
            if not encrypted_data:
                break

            decrypted_data = decryptor.update(encrypted_data)

            # Unpad only the last chunk of data
            if bytes_received + len(encrypted_data) >= file_size:
                unpadder = PKCS7(128).unpadder()
                decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

            f.write(decrypted_data)
            bytes_received += len(decrypted_data)  # Modify this line

        f.write(decryptor.finalize())

    print(f"File '{filename}' uploaded successfully to the 'uploads' directory.")
    client_socket.sendall(b"ACK")




# Download handler function
def handle_download(client_socket, shared_key, filename):
    # Create a file path for the downloaded file
    file_path = os.path.join("downloads", filename)

    # Initialize AES cipher with shared_key and a random IV
    iv = client_socket.recv(16)  # Receive the IV from the client
    aes_cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    # Open the file and send the encrypted data to the client
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

    print(f"File '{filename}' downloaded successfully.")

#Server setup and main loop

params = generate_parameters()
server_private_key = generate_private_key(params)
server_public_key = generate_public_key(server_private_key)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 12345))
server.listen(1)

print("Server listening on port 12345...")

while True:
    client, address = server.accept()
    print("Client connected from", address)

    client.sendall(params.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3))
    client.sendall(server_public_key)
    client_public_key = client.recv(4096)

    shared_key = derive_shared_key(server_private_key, client_public_key)
    # Print the shared key information
    print("Shared key:", shared_key.hex())
    print("Key size:", len(shared_key) * 8, "bits")

    while True:
        request_data = client.recv(1024)
        if not request_data:
            break

        iv = request_data[:16]
        encrypted_request_data = request_data[16:]
        _, decryptor, _ = create_encryptor_decryptor(shared_key, iv)
        request = decryptor.update(encrypted_request_data) + decryptor.finalize()
        request = request.decode("utf-8").strip()

        if request.startswith("DOWNLOAD:"):
            filename = request[9:]
            handle_download(client, shared_key, filename)
        elif request.startswith("UPLOAD:"):
            filename = request[7:]
            handle_upload(client, shared_key, filename)
        else:
            print(f"Unknown request: {request}")

    print("Closing connection with", address)
    client.close()

