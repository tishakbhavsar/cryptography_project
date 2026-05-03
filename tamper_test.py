"""Demo: shows that the Encrypt-then-MAC layer rejects tampered ciphertext.

Runs a server and client Peer in the same process (no terminals, no input()),
completes the real handshake, then:
  1. sends a clean message  -> decrypts fine
  2. flips a bit in the MAC tag -> rejected
  3. flips a bit in the ciphertext -> rejected

Run from this directory:
    python tamper_test.py
"""
import threading
import time

from peer import Peer

PORT = 5601


def run_server(box):
    s = Peer(is_server=True, host="127.0.0.1", port=PORT)
    s.start  # touch attribute to keep linters quiet; real start is below
    s.sock.bind((s.host, s.port))
    s.sock.listen(1)
    s.conn, _ = s.sock.accept()
    from peer import load_peer_public
    s.peer_verify_key = load_peer_public(s.peer_role)
    s._handshake()
    box["s"] = s


def main():
    # Make sure both identities exist before either side handshakes.
    Peer(is_server=False, host="127.0.0.1", port=PORT)
    Peer(is_server=True,  host="127.0.0.1", port=PORT)

    box = {}
    threading.Thread(target=run_server, args=(box,), daemon=True).start()
    time.sleep(0.2)

    c = Peer(is_server=False, host="127.0.0.1", port=PORT)
    c.sock.connect((c.host, c.port))
    c.conn = c.sock
    from peer import load_peer_public
    c.peer_verify_key = load_peer_public(c.peer_role)
    c._handshake()

    while "s" not in box:
        time.sleep(0.05)
    s = box["s"]

    # 1. honest message
    c._send_frame(c.encrypt_then_mac(b"hello server"))
    print(f"[ok] honest message decrypted -> {s.verify_then_decrypt(s._recv_frame())!r}")

    # 2. flip a tag bit
    blob = bytearray(c.encrypt_then_mac(b"this should be rejected"))
    blob[-1] ^= 0x01
    c._send_frame(bytes(blob))
    try:
        s.verify_then_decrypt(s._recv_frame())
        print("[FAIL] tampered tag was accepted")
    except Exception as e:
        print(f"[ok] tampered tag rejected -> {type(e).__name__}: {e}")

    # 3. flip a ciphertext bit
    blob = bytearray(c.encrypt_then_mac(b"another bad one"))
    blob[20] ^= 0x01
    c._send_frame(bytes(blob))
    try:
        s.verify_then_decrypt(s._recv_frame())
        print("[FAIL] tampered ciphertext was accepted")
    except Exception as e:
        print(f"[ok] tampered ciphertext rejected -> {type(e).__name__}: {e}")

    c.conn.close()
    s.conn.close()


if __name__ == "__main__":
    main()
