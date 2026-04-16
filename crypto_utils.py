from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib


def generate_rsa_keypair():
    # supports tunnel and post by creating rsa keys for both sides
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    # used for the tunnel command
    # convert public key to bytes for transmission
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(public_key_bytes):
    # used for the tunnel command
    # convert received bytes back into public key object
    return serialization.load_pem_public_key(public_key_bytes)


def encrypt_message(public_key, message_bytes):
    # used for the post command
    # encrypt message using rsa with oaep padding
    return public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_message(private_key, encrypted_bytes):
    # used for the post command
    # decrypt message using rsa private key
    return private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def compute_sha256(message_text):
    # used for the displays secure/compromised correctly
    # compute sha256 hash of a string for integrity checking
    return hashlib.sha256(message_text.encode()).hexdigest()