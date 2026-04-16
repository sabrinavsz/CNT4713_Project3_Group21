import socket
import sys
import os

# allow importing from root folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    decrypt_message,
    encrypt_message,
    compute_sha256
)

HOST = '127.0.0.1'
PORT = 8080


def recv_exact(connection, num_bytes):
    # helper to ensure we read exact number of bytes from socket
    data = b""
    while len(data) < num_bytes:
        packet = connection.recv(num_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data


def start_server():
    print("Starting server...")

    # generate rsa keys for secure communication
    print("Creating RSA keypair")
    server_private_key, server_public_key = generate_rsa_keypair()
    print("RSA keypair created")

    # create main server socket
    print("Creating server socket")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print("Awaiting connections...")

    # accept initial control connection
    conn, addr = server_socket.accept()

    # receive command from client
    command = conn.recv(1024).decode()

    # connect command
    if command == "connect":
        print("Connection requested. Creating data socket")

        # send new port for data communication
        data_port = 9090
        conn.send(str(data_port).encode())

        # create data socket for actual communication
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.bind((HOST, data_port))
        data_socket.listen()

        # accept data connection
        data_conn, data_addr = data_socket.accept()

        # tunnel command
        # wait for tunnel command for key exchange
        tunnel_command = data_conn.recv(1024).decode()

        if tunnel_command == "tunnel":
            print("Tunnel requested. Sending public key")

            # receive client's public key
            client_public_key_bytes = data_conn.recv(4096)
            client_public_key = deserialize_public_key(client_public_key_bytes)

            # send server public key back
            server_public_key_bytes = serialize_public_key(server_public_key)
            data_conn.send(server_public_key_bytes)

            # post command
            # wait for post command for encrypted message transfer
            post_command = data_conn.recv(1024).decode()

            if post_command == "post":
                print("Post requested.")

                # receive encrypted message (fixed size for rsa)
                encrypted_message = recv_exact(data_conn, 256)
                print(f"Received encrypted message: {encrypted_message.hex()}")

                # decrypt message using server private key
                decrypted_message_bytes = decrypt_message(server_private_key, encrypted_message)
                decrypted_message = decrypted_message_bytes.decode()
                print(f"Decrypted message: {decrypted_message}")

                # compute sha256 hash of plaintext
                print("Computing hash")
                message_hash = compute_sha256(decrypted_message)
                print(f"Responding with hash: {message_hash}")

                # encrypt hash using client public key
                encrypted_hash = encrypt_message(client_public_key, message_hash.encode())

                # send encrypted hash back to client for verification
                data_conn.send(encrypted_hash)

        # close data connection
        data_conn.close()
        data_socket.close()

    # close control connection
    conn.close()
    server_socket.close()


if __name__ == "__main__":
    start_server()