import socket
import sys
import os

# allow importing from root folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    encrypt_message,
    decrypt_message,
    compute_sha256
)

HOST = '127.0.0.1'
PORT = 8080


def recv_exact(connection, num_bytes):
    # helper to receive exact number of bytes
    data = b""
    while len(data) < num_bytes:
        packet = connection.recv(num_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data


def start_client():
    print("Starting client...")

    # generate rsa keys for secure communication
    print("Creating RSA keypair")
    client_private_key, client_public_key = generate_rsa_keypair()
    print("RSA keypair created")

    print("Creating client socket")

    # create control socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Connecting to server")

    # connect command
    # connect to server and request communication setup
    client_socket.connect((HOST, PORT))
    client_socket.send("connect".encode())

    # receive data port from server
    data_port = int(client_socket.recv(1024).decode())

    print("Creating data socket")

    # create data socket connection
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket.connect((HOST, data_port))

    print("Requesting tunnel")

    # tunnel command
    # send tunnel command to start key exchange
    data_socket.send("tunnel".encode())

    # send client public key
    client_public_key_bytes = serialize_public_key(client_public_key)
    data_socket.send(client_public_key_bytes)

    # receive server public key
    server_public_key_bytes = data_socket.recv(4096)
    server_public_key = deserialize_public_key(server_public_key_bytes)

    print("Server public key received")
    print("Tunnel established")

    # message to send
    message = "Hello"
    print(f"Encrypting message: {message}")

    # encrypt message using server public key
    encrypted_message = encrypt_message(server_public_key, message.encode())

    # post command
    # send post command and encrypted message to server
    data_socket.send("post".encode())

    print(f"Sending encrypted message: {encrypted_message.hex()}")

    # send encrypted message
    data_socket.send(encrypted_message)

    # receive encrypted hash from server
    encrypted_hash = recv_exact(data_socket, 256)

    print("Received hash")
    print("Computing hash")

    # decrypt hash using client private key
    received_hash = decrypt_message(client_private_key, encrypted_hash).decode()

    # compute local hash
    local_hash = compute_sha256(message)

    # displays secure/compromised correctly
    # compare hashes to verify integrity
    if received_hash == local_hash:
        print("Secure")
    else:
        print("Compromised")

    # close sockets
    data_socket.close()
    client_socket.close()


if __name__ == "__main__":
    start_client()