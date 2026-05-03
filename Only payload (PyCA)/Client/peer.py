import os
import socket
import struct
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()
AES_KEY_LEN = 16   # AES-128
MAC_KEY_LEN = 32   # HMAC-SHA256
IV_LEN = 16
TAG_LEN = 32
LEN_HDR = 4


def _load_or_create_identity(priv_path, pub_path):
    if os.path.exists(priv_path):
        with open(priv_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = ec.generate_private_key(CURVE)
    os.makedirs(os.path.dirname(priv_path) or '.', exist_ok=True)
    with open(priv_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(pub_path, 'wb') as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"[*] Generated new identity key at {priv_path}")
    return key


def _load_peer_public(pub_path):
    with open(pub_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


class Peer:
    def __init__(self, is_server, host='127.0.0.1', port=5002,
                 my_priv_path=None, peer_pub_path=None):
        self.sock = socket.socket()
        self.is_server = is_server
        self.host = host
        self.port = port

        keys_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), '..', 'keys')
        os.makedirs(keys_dir, exist_ok=True)
        my_role = 'server' if is_server else 'client'
        peer_role = 'client' if is_server else 'server'
        my_priv_path = my_priv_path or os.path.join(keys_dir, f'{my_role}_priv.pem')
        my_pub_path = os.path.join(keys_dir, f'{my_role}_pub.pem')
        peer_pub_path = peer_pub_path or os.path.join(keys_dir, f'{peer_role}_pub.pem')

        self.my_signing_key = _load_or_create_identity(my_priv_path, my_pub_path)
        self._peer_pub_path = peer_pub_path

        print(self.host)

    def start(self):
        if self.is_server:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            print("[*] Waiting for connection...")
            conn, _ = self.sock.accept()
            self.conn = conn
        else:
            self.sock.connect((self.host, self.port))
            self.conn = self.sock

        # Peer's long-term public key must exist by handshake time.
        if not os.path.exists(self._peer_pub_path):
            raise FileNotFoundError(
                f"Peer public key not found at {self._peer_pub_path}. "
                "Start the other side once to auto-generate it.")
        self.peer_verify_key = _load_peer_public(self._peer_pub_path)

        self._handshake()
        self._start_threads()

    # --- framing ---

    def _send_frame(self, data):
        self.conn.sendall(struct.pack('>I', len(data)) + data)

    def _recv_exact(self, n):
        buf = b''
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
        (length,) = struct.unpack('>I', hdr)
        return self._recv_exact(length)

    # --- authenticated key exchange: signed ephemeral ECDH ---

    def _handshake(self):
        eph_priv = ec.generate_private_key(CURVE)
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        signature = self.my_signing_key.sign(
            eph_pub_bytes, ec.ECDSA(hashes.SHA256()))

        self._send_frame(eph_pub_bytes)
        self._send_frame(signature)

        peer_eph_pub_bytes = self._recv_frame()
        peer_sig = self._recv_frame()
        if peer_eph_pub_bytes is None or peer_sig is None:
            raise ConnectionError("Handshake aborted: peer disconnected")

        try:
            self.peer_verify_key.verify(
                peer_sig, peer_eph_pub_bytes, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ConnectionError("Handshake failed: invalid peer signature")

        peer_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE, peer_eph_pub_bytes)
        shared = eph_priv.exchange(ec.ECDH(), peer_eph_pub)

        # Sort transcript so both sides assign send/recv keys consistently.
        a, b = sorted([eph_pub_bytes, peer_eph_pub_bytes])
        keys = HKDF(
            algorithm=hashes.SHA256(),
            length=2 * (AES_KEY_LEN + MAC_KEY_LEN),
            salt=a + b,
            info=b'etm-aes128-cbc-hmac-sha256',
        ).derive(shared)
        k1_enc = keys[0:AES_KEY_LEN]
        k1_mac = keys[AES_KEY_LEN:AES_KEY_LEN + MAC_KEY_LEN]
        k2_enc = keys[AES_KEY_LEN + MAC_KEY_LEN:2 * AES_KEY_LEN + MAC_KEY_LEN]
        k2_mac = keys[2 * AES_KEY_LEN + MAC_KEY_LEN:]

        if eph_pub_bytes == a:
            self.send_enc_key, self.send_mac_key = k1_enc, k1_mac
            self.recv_enc_key, self.recv_mac_key = k2_enc, k2_mac
        else:
            self.send_enc_key, self.send_mac_key = k2_enc, k2_mac
            self.recv_enc_key, self.recv_mac_key = k1_enc, k1_mac

        print("[*] Handshake complete: peer authenticated, session keys established.")

    # --- encrypt-then-MAC record layer ---

    def _encrypt_then_mac(self, plaintext):
        iv = os.urandom(IV_LEN)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc = Cipher(algorithms.AES(self.send_enc_key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()

        h = hmac.HMAC(self.send_mac_key, hashes.SHA256())
        h.update(iv + ct)
        tag = h.finalize()
        return iv + ct + tag

    def _verify_then_decrypt(self, blob):
        if len(blob) < IV_LEN + TAG_LEN:
            raise ValueError("ciphertext too short")
        iv = blob[:IV_LEN]
        tag = blob[-TAG_LEN:]
        ct = blob[IV_LEN:-TAG_LEN]

        h = hmac.HMAC(self.recv_mac_key, hashes.SHA256())
        h.update(iv + ct)
        h.verify(tag)  # constant-time; raises InvalidSignature on mismatch

        dec = Cipher(algorithms.AES(self.recv_enc_key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    # --- chat loops ---

    def _start_threads(self):
        threading.Thread(target=self._receive_loop, daemon=True).start()
        print("I'm ready")
        self._send_loop()

    def _receive_loop(self):
        while True:
            try:
                blob = self._recv_frame()
                if blob is None:
                    print("\n[Peer disconnected]")
                    break
                plaintext = self._verify_then_decrypt(blob)
                message = plaintext.decode()
                if message.strip().lower() == "exit":
                    print("\n[Peer exited]")
                    break
                print(f"\n[Peer]: {message}")
            except Exception as e:
                print(f"[Receive error]: {e}")
                break

    def _send_loop(self):
        while True:
            try:
                msg = input("You: ").strip()
                blob = self._encrypt_then_mac(msg.encode())
                self._send_frame(blob)
                if msg.lower() == "exit":
                    break
            except Exception as e:
                print(f"[Send error]: {e}")
                break

        self.conn.close()
        self.sock.close()
        print("[*] Connection closed.")
