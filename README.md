# Secure Messenger (PyCA)

A small TCP chat program that implements the assignment's required crypto suite:

- **Authenticated key exchange** — ephemeral ECDH on NIST P-256, authenticated with ECDSA signatures over the ephemeral public key (signed Diffie–Hellman).
- **Authenticated encryption** — Encrypt-then-MAC with **AES-128-CBC** for confidentiality and **HMAC-SHA256** for integrity.

Built on the [`cryptography`](https://cryptography.io) (PyCA) library only.

---

## Files

```
peer.py          # Peer class: TCP, signed-ECDH handshake, encrypt-then-MAC
messenger.py     # entry point: `python messenger.py server|client ...`
tamper_test.py   # demo: shows that bit-flipped ciphertext is rejected
README.md        # you are here
keys/            # auto-generated ECDSA identity keys (NEVER commit private keys)
```

Two real source files, one demo, one README.

---

## Quick start (one machine, two terminals)

```bash
# one-time setup
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography

# terminal A — server
python messenger.py server 127.0.0.1

# terminal B — client (activate venv first)
source .venv/bin/activate
python messenger.py client 127.0.0.1
```

Type messages in either terminal; they appear on the other side after being encrypted, MAC-tagged, sent, MAC-verified, and decrypted. Type `exit` to quit.

The very first run on each role auto-generates the long-term ECDSA keys into `keys/`.

---

## Running across two computers

The crypto and TCP work fine across machines. The one extra step is **swapping public keys** so each side knows whose signature to trust. Public keys are *not* secret — copy them however you like (USB, scp, email, Slack).

Assume **Alice's machine = server**, **Bob's machine = client**, both on the same LAN.

1. **On Alice (server)** — start it once to generate her identity, then leave it running:
   ```bash
   python messenger.py server
   # prints e.g. "[INFO] Server host: 10.1.57.116  port: 5002"
   # also creates keys/server_priv.pem and keys/server_pub.pem
   ```

2. **On Bob (client)** — try to connect once. It will fail with a missing-key error, but in the process it generates Bob's own identity:
   ```bash
   python messenger.py client 10.1.57.116
   # FileNotFoundError: keys/server_pub.pem  (expected on first run)
   # but keys/client_priv.pem and keys/client_pub.pem now exist
   ```

3. **Swap the public keys** (one-time):
   - Copy `keys/server_pub.pem` from Alice's machine into Bob's `keys/` directory.
   - Copy `keys/client_pub.pem` from Bob's machine into Alice's `keys/` directory.

4. **Connect for real**:
   ```bash
   # Alice
   python messenger.py server

   # Bob
   python messenger.py client 10.1.57.116
   ```
   Both should print `Handshake complete: peer authenticated, session keys established.`

> **Never copy `*_priv.pem` files** — those are private. Only the `*_pub.pem` files are meant to be shared.

> **Firewall / NAT**: on the same Wi-Fi LAN this just works. Across the internet you'd need port forwarding or a VPN; that's outside the scope of the assignment.

---

## Demo: tamper rejection

After the messenger has been run at least once (so the keys exist):

```bash
source .venv/bin/activate
python tamper_test.py
```

Expected output:

```
[ok] honest message decrypted -> b'hello server'
[ok] tampered tag rejected -> InvalidSignature: Signature did not match digest.
[ok] tampered ciphertext rejected -> InvalidSignature: Signature did not match digest.
```

This proves Encrypt-then-MAC is doing its job: any single-bit modification to the IV, ciphertext, or tag causes the receiver's `HMAC.verify` to raise **before** AES decryption is attempted.

---

## CLI reference

```
python messenger.py server [host] [port]
python messenger.py client <host> [port]
```

- `host` defaults to the machine's detected LAN IP (server) or is required (client).
- `port` defaults to `5002`.

---

## What the assignment maps to in the code

| Assignment requirement | Where in `peer.py` |
|---|---|
| ECDH (key agreement) | `_handshake()`: `ec.generate_private_key(CURVE)` + `eph_priv.exchange(ec.ECDH(), peer_pub)` |
| ECDSA (authentication of the ECDH) | `signing_key.sign(...)` and `peer_verify_key.verify(...)` in `_handshake()` |
| Encrypt-then-MAC | `encrypt_then_mac()` and `verify_then_decrypt()` (verify *before* decrypt) |
| AES-128-CBC | `Cipher(algorithms.AES(send_enc), modes.CBC(iv))`, 16-byte key |
| HMAC-SHA256 | `hmac.HMAC(send_mac, hashes.SHA256())`, 32-byte key |

Extra hygiene already in place: ephemeral DH for **forward secrecy**, **HKDF-SHA256** for key derivation (never use raw DH output as a key), fresh random IV per message, **separate keys per direction**, MAC computed over `IV || ciphertext`, **constant-time** tag verification.

---

## Troubleshooting

- **`Connection refused`** — the server is listening on its LAN IP, not `127.0.0.1`. Either pass `127.0.0.1` to the server too (`python messenger.py server 127.0.0.1`), or have the client connect to whatever IP the server printed.
- **`FileNotFoundError: keys/<role>_pub.pem`** — the peer hasn't shared their long-term public key with this machine yet. See the cross-computer instructions above.
- **`InvalidSignature` during handshake** — the public key you have for the peer doesn't match the private key the peer is actually using. Re-copy the correct `*_pub.pem`.
- **`ModuleNotFoundError: cryptography`** — the venv isn't active, or `pip install cryptography` wasn't run inside it.
