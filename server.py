import socket
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import re


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


# Upload handler function
def handle_upload(client_socket, shared_key, filename):
    # Unpad the filename
    print(filename)
    filename = re.sub(r'[^\x20-\x7E]+', '', filename)
    print(filename)
    unpadder = padding.PKCS7(128).unpadder()

    # Create a file path for the uploaded file
    file_path = os.path.join("uploads", filename)
    print("here 1")
    # Initialize AES cipher with shared_key and a random IV
    aes_cipher = Cipher(algorithms.AES(shared_key), modes.CBC(os.urandom(16)), backend=default_backend())
    decryptor = aes_cipher.decryptor()
    print("here 2")
    # Open the file and write the decrypted data to it
    with open(file_path, "wb") as f:
        while True:
            data = client_socket.recv(1024)
            print("data:",data)
            if not data:
                break
            decrypted_data = decryptor.update(data)
            print("decrypted data:",decrypted_data)
            unpadded_data = unpadder.update(decrypted_data)
            print("unpadded data:",unpadded_data)
            f.write(unpadded_data)

        f.write(unpadder.finalize())
        
    print(f"File '{filename}' uploaded successfully to the 'uploads' directory.")



# Download handler function
def handle_download(client_socket, shared_key, filename):
    # Create a file path for the downloaded file
    file_path = os.path.join("downloads", filename)

    # Initialize AES cipher with shared_key and a random IV
    aes_cipher = Cipher(algorithms.AES(shared_key), modes.CBC(os.urandom(16)), backend=default_backend())
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

