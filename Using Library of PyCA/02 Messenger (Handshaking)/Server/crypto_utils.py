from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_public_key(pem_bytes):
    """Loads and returns a PEM public key."""
    return serialization.load_pem_public_key(pem_bytes)

# ---------- Key Generation ----------

def generate_ephemeral_keypair():
    """Generates ECDSA keypair (P-256) for key exchange."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pub_bytes


def generate_signing_keypair():
    """Generates an ECDSA signing keypair (P-256). Returns (priv, pub_pem)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_pem


def sign_data(private_key, data: bytes) -> bytes:
    """Signs data with ECDSA (SHA256) and returns signature bytes."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    pub = serialization.load_pem_public_key(public_pem)
    try:
        pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False



# ---------- Key Exchange (ECDH) ----------

def perform_key_exchange(my_private_key, peer_public_pem):
    """Derives shared session key using ECDH and HKDF."""
    peer_public_key = serialization.load_pem_public_key(peer_public_pem)
    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)
    # Derive 48 bytes: 16 bytes AES-128 key + 32 bytes HMAC-SHA256 key
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=None,
        info=b'p2p chat'
    ).derive(shared_secret)

    aes_key = derived[:16]
    hmac_key = derived[16:]
    return aes_key, hmac_key


# ---------- Encrypt-then-MAC (AES-128-CBC + HMAC-SHA256) ----------
def encrypt_then_mac(plaintext: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = HMAC(hmac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    tag = h.finalize()

    return iv + ciphertext + tag


def verify_and_decrypt(blob: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    if len(blob) < 16 + 32:
        raise ValueError("Ciphertext too short")
    iv = blob[:16]
    tag = blob[-32:]
    ciphertext = blob[16:-32]

    h = HMAC(hmac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    h.verify(tag)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext




    

