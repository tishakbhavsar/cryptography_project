import subprocess
import os

def generate_ephemeral_keypair(mode):
    """
    Generates an ephemeral ECDH key pair using OpenSSL and returns the public key bytes.
    
    Parameters:
        mode (bool): If True, use "Server_keys" directory; otherwise, "Client_keys".
    
    Returns:
        bytes: The PEM-encoded public key.
    """
    # Choose directory based on role
    key_dir = "Server_keys" if mode else "Client_keys"
    os.makedirs(key_dir, exist_ok=True)

    private_path = os.path.join(key_dir, "private.pem")
    public_path = os.path.join(key_dir, "public.pem")

    # Generate the ephemeral private key using the NIST P-256 curve
    subprocess.run([
        "openssl", "ecparam",
        "-name", "prime256v1",
        "-genkey", "-noout",
        "-out", private_path
    ], check=True)

    # Derive and save the corresponding public key in PEM format
    subprocess.run([
        "openssl", "ec",
        "-in", private_path,
        "-pubout",
        "-out", public_path
    ], check=True)

    # Load the public key to send over the network
    with open(public_path, "rb") as f:
        pub_bytes = f.read()

    return pub_bytes


def perform_key_exchange(peer_pub_bytes, mode):
    """
    Performs ECDH key exchange with a received peer public key using OpenSSL.
    
    Parameters:
        peer_pub_bytes (bytes): The peer's public key in PEM format.
        mode (bool): If True, use "Server_keys" directory; otherwise, "Client_keys".
    
    Returns:
        bytes: The raw shared secret derived from ECDH.
    """
    # Choose key directory based on server/client role
    key_dir = "Server_keys" if mode else "Client_keys"
    private_path = os.path.join(key_dir, "private.pem")
    peer_public_path = os.path.join(key_dir, "peer_public.pem")
    session_key_path = os.path.join(key_dir, "shared_secret.bin")

    # Write the received peer public key to file (so OpenSSL can use it)
    with open(peer_public_path, "wb") as f:
        f.write(peer_pub_bytes)

    # Use OpenSSL to derive the shared secret using ECDH
    subprocess.run([
        "openssl", "pkeyutl",
        "-derive",
        "-inkey", private_path,
        "-peerkey", peer_public_path,
        "-out", session_key_path
    ], check=True)

    # Load and return the shared secret
    with open(session_key_path, "rb") as f:
        return f.read()



