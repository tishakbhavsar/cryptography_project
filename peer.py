"""Authenticated, encrypted TCP messenger.

Crypto suite (assignment-mandated):
  * Authenticated key exchange : ECDH(P-256) authenticated by ECDSA(P-256)
  * Authenticated encryption   : Encrypt-then-MAC, AES-128-CBC + HMAC-SHA256

Wire format
-----------
Every logical message is sent as a 4-byte big-endian length prefix
followed by that many bytes (TCP is a byte stream; we frame it).

Handshake (right after TCP connect, before any chat traffic):
    -> ephemeral_ecdh_pub_bytes      (X9.62 uncompressed point)
    -> ECDSA_signature(over the bytes above, with my long-term key)
    <- peer_ephemeral_ecdh_pub_bytes
    <- peer_ECDSA_signature
  Then both sides:
    - verify peer's signature with peer's long-term ECDSA pubkey
    - compute ECDH shared secret
    - HKDF-SHA256 -> 4 keys (enc+mac per direction)

Per chat message:
    blob = IV(16) || AES-128-CBC(PKCS7(plaintext)) || HMAC-SHA256(IV || CT)
    receiver verifies the MAC (constant-time) BEFORE decrypting.
"""
import os
import socket
import struct
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()      # NIST P-256, used for both ECDSA and ECDH
AES_KEY_LEN = 16            # AES-128
MAC_KEY_LEN = 32            # HMAC-SHA256 key
IV_LEN = 16                 # AES block size
TAG_LEN = 32                # SHA-256 output
LEN_HDR = 4                 # bytes of big-endian length prefix

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


# --------------------------------------------------------------------------- #
# Long-term ECDSA identity keys (one per role, persisted to disk).
# --------------------------------------------------------------------------- #

def _identity_paths(role):
    """Return (private_path, public_path) for 'server' or 'client'."""
    return (
        os.path.join(KEYS_DIR, f"{role}_priv.pem"),
        os.path.join(KEYS_DIR, f"{role}_pub.pem"),
    )


def load_or_create_identity(role):
    """Load this side's long-term ECDSA keypair, generating one on first run."""
    priv_path, pub_path = _identity_paths(role)
    os.makedirs(KEYS_DIR, exist_ok=True)

    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    key = ec.generate_private_key(CURVE)
    with open(priv_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(pub_path, "wb") as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"[*] Generated new {role} identity at {priv_path}")
    return key


def load_peer_public(peer_role):
    """Load the *peer's* long-term ECDSA public key (used to verify their signature)."""
    _, pub_path = _identity_paths(peer_role)
    if not os.path.exists(pub_path):
        raise FileNotFoundError(
            f"Peer public key not found: {pub_path}\n"
            f"Run the {peer_role} side once (it generates its own keys), then copy "
            f"{peer_role}_pub.pem into this machine's keys/ directory."
        )
    with open(pub_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# --------------------------------------------------------------------------- #
# Peer
# --------------------------------------------------------------------------- #

class Peer:
    def __init__(self, is_server, host, port=5002):
        self.is_server = is_server
        self.host = host
        self.port = port
        self.sock = socket.socket()

        self.role = "server" if is_server else "client"
        self.peer_role = "client" if is_server else "server"

        # Make sure our identity exists. Peer's pubkey is loaded later, after connect.
        self.signing_key = load_or_create_identity(self.role)

    # ----- connection lifecycle -----

    def start(self):
        if self.is_server:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            print(f"[*] Listening on {self.host}:{self.port} ...")
            self.conn, addr = self.sock.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
        else:
            print(f"[*] Connecting to {self.host}:{self.port} ...")
            self.sock.connect((self.host, self.port))
            self.conn = self.sock

        self.peer_verify_key = load_peer_public(self.peer_role)
        self._handshake()
        self._chat_forever()

    # ----- TCP framing -----

    def _send_frame(self, data):
        self.conn.sendall(struct.pack(">I", len(data)) + data)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _recv_frame(self):
        hdr = self._recv_exact(LEN_HDR)
        if hdr is None:
            return None
        (length,) = struct.unpack(">I", hdr)
        return self._recv_exact(length)

    # ----- (a) authenticated key exchange: signed ephemeral ECDH -----

    def _handshake(self):
        # 1. Ephemeral ECDH key (thrown away after the handshake -> forward secrecy).
        eph_priv = ec.generate_private_key(CURVE)
        eph_pub = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # 2. Sign the ephemeral pub with our long-term ECDSA key (this is what
        #    authenticates the DH; without it, MITM is possible).
        signature = self.signing_key.sign(eph_pub, ec.ECDSA(hashes.SHA256()))

        # 3. Exchange ephemeral pubs and signatures.
        self._send_frame(eph_pub)
        self._send_frame(signature)
        peer_eph_pub = self._recv_frame()
        peer_sig = self._recv_frame()
        if peer_eph_pub is None or peer_sig is None:
            raise ConnectionError("handshake aborted: peer disconnected")

        # 4. Verify the peer signed THEIR ephemeral pub with the long-term key
        #    we trust for them. Raises InvalidSignature on mismatch -> abort.
        try:
            self.peer_verify_key.verify(
                peer_sig, peer_eph_pub, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ConnectionError("handshake failed: invalid peer signature")

        # 5. ECDH shared secret.
        peer_pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, peer_eph_pub)
        shared = eph_priv.exchange(ec.ECDH(), peer_pub_obj)

        # 6. HKDF-SHA256 -> 4 session keys (enc+mac per direction).
        #    Salting with both ephemeral pubs (sorted) binds keys to *this* handshake.
        a, b = sorted([eph_pub, peer_eph_pub])
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=2 * (AES_KEY_LEN + MAC_KEY_LEN),
            salt=a + b,
            info=b"etm-aes128-cbc-hmac-sha256",
        ).derive(shared)
        k1_enc = derived[0:AES_KEY_LEN]
        k1_mac = derived[AES_KEY_LEN:AES_KEY_LEN + MAC_KEY_LEN]
        k2_enc = derived[AES_KEY_LEN + MAC_KEY_LEN:2 * AES_KEY_LEN + MAC_KEY_LEN]
        k2_mac = derived[2 * AES_KEY_LEN + MAC_KEY_LEN:]

        # Side whose ephemeral pub sorts smaller takes (k1_*) as its send-keys;
        # this is a deterministic way for both sides to agree on directions
        # without an extra "I'm Alice / I'm Bob" round-trip.
        if eph_pub == a:
            self.send_enc, self.send_mac = k1_enc, k1_mac
            self.recv_enc, self.recv_mac = k2_enc, k2_mac
        else:
            self.send_enc, self.send_mac = k2_enc, k2_mac
            self.recv_enc, self.recv_mac = k1_enc, k1_mac

        print("[*] Handshake complete: peer authenticated, session keys established.")

    # ----- (b) authenticated encryption: Encrypt-then-MAC -----

    def encrypt_then_mac(self, plaintext):
        iv = os.urandom(IV_LEN)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        enc = Cipher(algorithms.AES(self.send_enc), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()

        h = hmac.HMAC(self.send_mac, hashes.SHA256())
        h.update(iv + ct)
        tag = h.finalize()

        return iv + ct + tag

    def verify_then_decrypt(self, blob):
        if len(blob) < IV_LEN + TAG_LEN:
            raise ValueError("ciphertext too short")
        iv, ct, tag = blob[:IV_LEN], blob[IV_LEN:-TAG_LEN], blob[-TAG_LEN:]

        # *** MAC verify FIRST (constant-time). Only if it passes do we decrypt. ***
        h = hmac.HMAC(self.recv_mac, hashes.SHA256())
        h.update(iv + ct)
        h.verify(tag)  # raises InvalidSignature on mismatch

        dec = Cipher(algorithms.AES(self.recv_enc), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    # ----- chat loop -----

    def _chat_forever(self):
        threading.Thread(target=self._recv_loop, daemon=True).start()
        print("[*] Ready. Type messages and hit enter. Type 'exit' to quit.")
        self._send_loop()

    def _recv_loop(self):
        while True:
            try:
                blob = self._recv_frame()
                if blob is None:
                    print("\n[Peer disconnected]")
                    break
                msg = self.verify_then_decrypt(blob).decode()
                if msg.strip().lower() == "exit":
                    print("\n[Peer exited]")
                    break
                print(f"\n[Peer]: {msg}")
            except Exception as e:
                print(f"[Receive error]: {e}")
                break

    def _send_loop(self):
        while True:
            try:
                msg = input("You: ").strip()
                self._send_frame(self.encrypt_then_mac(msg.encode()))
                if msg.lower() == "exit":
                    break
            except (EOFError, KeyboardInterrupt):
                break
            except Exception as e:
                print(f"[Send error]: {e}")
                break

        try:
            self.conn.close()
            self.sock.close()
        except OSError:
            pass
        print("[*] Connection closed.")
