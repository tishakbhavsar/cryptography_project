# Secure Messenger

A small TCP chat program that does signed Diffie-Hellman over an elliptic curve to set up a session, then sends every chat message under AES-128-CBC with an HMAC-SHA256 tag (encrypt-then-MAC). Built with the PyCA `cryptography` library — no other dependencies.

This is the assignment from the cryptography course: take an existing plaintext messenger and plug in a real authenticated, encrypted channel.

## What's in here

```
Using Library of PyCA/
├── 01 Messenger (only payload)/         the original plaintext starter (no crypto)
│   ├── Server/  peer.py + alt_run_server.py
│   └── Client/  peer.py + alt_run_client.py
└── 02 Messenger (Handshaking)/          the version with our crypto plugged in
    ├── Server/  peer.py + alt_run_server.py
    └── Client/  peer.py + alt_run_client.py
```

`peer.py` in the `02 Messenger (Handshaking)` folders contains the full crypto: signed-ECDH handshake, AES-128-CBC + HMAC-SHA256 record layer, length-prefixed framing. Server and Client copies are identical — same file, two locations, just to keep the original starter layout.

The `alt_run_*.py` scripts are tiny entry points that figure out the local IP and instantiate a `Peer`.

When you first run the messenger, it auto-creates a `keys/` folder inside `02 Messenger (Handshaking)/` for the long-term ECDSA identity files. `keys/` is gitignored. Public keys can be shared (that's how the two sides know who to trust); private keys never leave the machine that made them.

## Setup

You only do this once, and only on each machine that's going to run the program.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

That's the whole installation. Activate the venv (`source .venv/bin/activate`) every time you open a new terminal.

## Running it on one machine

Open two terminals. In both, activate the venv.

Terminal 1 (server):
```bash
cd "Using Library of PyCA/02 Messenger (Handshaking)/Server"
python alt_run_server.py
```

It will print something like `[INFO] Detected IP: 10.1.57.116`. **Note that IP** — the client needs it.

Terminal 2 (client):
```bash
cd "Using Library of PyCA/02 Messenger (Handshaking)/Client"
python alt_run_client.py client 10.1.57.116        # use the IP the server printed
```

Both sides should print `Handshake complete: peer authenticated, session keys established.` and you can start typing. Type `exit` (or close the terminal) to quit.

The first time you run anything, the program creates `keys/server_priv.pem`, `keys/server_pub.pem`, `keys/client_priv.pem`, and `keys/client_pub.pem` inside `02 Messenger (Handshaking)/keys/`. After that it just loads them.

> Note: `alt_run_server.py` always binds to the machine's detected LAN IP, not loopback. So even on one machine, the client must connect to that detected IP rather than `127.0.0.1`.

## Running it across two machines

The same code runs on two different computers. The TCP socket doesn't care; the crypto doesn't care. The one extra step is that each side has to know the other's long-term public key, since that's what we use to verify the signed handshake. Public keys are not secret — share them however you want.

The two machines have to be reachable to each other on the network. Easiest is being on the same Wi-Fi or sharing a phone hotspot. Different Wi-Fi networks (or campus networks with client isolation turned on) won't work without something like Tailscale or a port-forwarded router, which is a separate problem.

Say one of you (Alice) is going to be the server, and the other (Bob) is the client. Both of you have the project cloned and the venv set up.

1. **On Alice's machine**, start the server. It generates Alice's keypair and starts listening:
   ```bash
   cd "Using Library of PyCA/02 Messenger (Handshaking)/Server"
   python alt_run_server.py
   ```
   Note the IP it prints — that's what Bob is going to connect to. You can leave the server running.

2. **On Bob's machine**, try the client once. It'll fail with a "peer public key not found" error, but along the way it generates Bob's keypair:
   ```bash
   cd "Using Library of PyCA/02 Messenger (Handshaking)/Client"
   python alt_run_client.py client <alice's ip>
   ```

3. **Swap the public keys.** Alice sends Bob her `02 Messenger (Handshaking)/keys/server_pub.pem`; Bob sends Alice his `02 Messenger (Handshaking)/keys/client_pub.pem`. AirDrop, email, Slack, USB stick — whatever. **Do not send the `_priv.pem` files.** Each side drops the received file into their own `02 Messenger (Handshaking)/keys/` folder.

4. **Now it works:**
   ```bash
   # on Alice
   cd "Using Library of PyCA/02 Messenger (Handshaking)/Server"
   python alt_run_server.py

   # on Bob
   cd "Using Library of PyCA/02 Messenger (Handshaking)/Client"
   python alt_run_client.py client <alice's ip>
   ```

If `ping <alice's ip>` from Bob's machine times out or says "no route to host," the network is the problem, not the program. Check you're really on the same Wi-Fi (same SSID, same first three numbers of the IP), or fall back to a phone hotspot.

## Running it over Tailscale (different networks)

If the two machines are on different Wi-Fi networks, a campus network with client isolation, or anywhere a direct LAN connection isn't possible, Tailscale gives you a private overlay network where each device gets a stable `100.x.x.x` IP that works regardless of which real network you're on.

### One-time setup

1. Install Tailscale on both machines: https://tailscale.com/download
2. On each machine, sign in with the same Tailscale account (or the same tailnet):
   ```bash
   tailscale up
   ```
3. Confirm connectivity — from either machine, ping the other using its Tailscale IP:
   ```bash
   tailscale ip          # see your own Tailscale IP
   ping 100.x.x.x        # ping the other machine's Tailscale IP
   ```

### Running the messenger over Tailscale

The server must bind to all interfaces (`0.0.0.0`) instead of the auto-detected LAN IP, so it accepts connections arriving on the Tailscale interface. Use `alt_run_server_tailscale.py` for this:

**On the server machine:**
```bash
cd "Using Library of PyCA/02 Messenger (Handshaking)/Server"
python alt_run_server_tailscale.py server
```

It will print your detected LAN IP, but what matters for the client is your **Tailscale IP** (run `tailscale ip` to find it).

**On the client machine:**
```bash
cd "Using Library of PyCA/02 Messenger (Handshaking)/Client"
python alt_run_client.py client 100.x.x.x    # use the server's Tailscale IP
```

Everything else (key exchange, the handshake, chatting) is identical to the local-network case. The TCP connection just travels through the Tailscale tunnel instead of your LAN.

> You still need to swap public keys the same way — Tailscale only handles the network layer. Trust ("who am I talking to?") is still anchored by the ECDSA keypairs in `keys/`.

## How the crypto fits together

When the TCP connection opens, before any chat traffic, the two sides run a handshake:

- Each side has a long-term **ECDSA P-256** keypair on disk (the files in `keys/`). This is the identity — "I am Alice."
- Each side generates a fresh, throwaway **ECDH P-256** keypair just for this session. This is what gives forward secrecy: even if the long-term key leaks later, recordings of past sessions stay unreadable, because the ephemeral keys are gone.
- Each side signs its ephemeral DH public key with its long-term ECDSA key and sends both the public key and the signature.
- Each side verifies the peer's signature using the peer's long-term ECDSA public key (the one we loaded from `keys/`). This is what stops a man-in-the-middle from substituting their own DH value — without the signature step, raw DH is unauthenticated and trivially MITM'd.
- ECDH then produces a shared secret. We run it through HKDF-SHA256 to derive four keys: an AES key and an HMAC key for each direction. Different keys per direction means a recorded "Alice to Bob" message can't be replayed back as a valid "Bob to Alice" message.

Once the handshake is done, every chat message goes through the same two helpers:

- `encrypt_then_mac`: pad to AES block size, encrypt under AES-128-CBC with a fresh random IV, then compute HMAC-SHA256 over `IV ‖ ciphertext`. Send `IV ‖ ciphertext ‖ tag`, length-prefixed so TCP framing is unambiguous.
- `verify_then_decrypt`: HMAC-verify first (constant-time, so an attacker can't forge tags one byte at a time by measuring how long verification takes). Only if the tag is valid do we run the AES decryption. Doing it the other way around is what causes padding-oracle attacks like the one that broke SSL 3.0.

## The math, in detail

### The curve we're using

Everything elliptic-curve in this project happens on **NIST P-256** (also called `secp256r1` or `prime256v1`). It's the curve

$$y^2 \;\equiv\; x^3 + ax + b \pmod{p}$$

with the specific NIST-standardised parameters

$$\begin{aligned}
p &= 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1 \\
a &= -3 \pmod{p} \\
b &= \texttt{0x5ac635d8...3bce3c3e}\ \text{(a 256-bit constant)} \\
n &= \text{order of the base point}\ G,\ \text{a 256-bit prime}
\end{aligned}$$

A "key" on this curve is just an integer $d \in [1, n-1]$. The corresponding public point is $Q = dG$, where $G$ is the standard base point and "multiplication" is repeated point addition on the curve. Recovering $d$ from $Q$ is the **elliptic-curve discrete log problem**, which has no known efficient classical algorithm.

### ECDH (key agreement)

Each side picks a fresh ephemeral private scalar and computes the matching public point:

$$d_A \xleftarrow{\$} [1, n-1], \quad Q_A = d_A G$$
$$d_B \xleftarrow{\$} [1, n-1], \quad Q_B = d_B G$$

They exchange $Q_A$ and $Q_B$ in the clear. Each side then computes

$$S = d_A Q_B = d_A (d_B G) = d_B (d_A G) = d_B Q_A$$

so both arrive at the same shared point $S$. The $x$-coordinate of $S$ is the raw shared secret. An eavesdropper sees only $Q_A$ and $Q_B$ and would need to solve EC-DLP (compute $d_A$ from $Q_A$) to derive $S$.

### ECDSA (signature)

Long-term signing key: $d \in [1, n-1]$. Verification key: $Q = dG$. To **sign** a message $m$ (here $m$ is the bytes of the ephemeral DH public key):

$$\begin{aligned}
e &= \mathrm{SHA{\text -}256}(m)\ \text{truncated to } \lceil \log_2 n \rceil\ \text{bits} \\
k &\xleftarrow{\$} [1, n-1] \\
(x_1, y_1) &= kG \\
r &= x_1 \bmod n \quad (\text{retry if } r = 0) \\
s &= k^{-1}(e + rd) \bmod n \quad (\text{retry if } s = 0)
\end{aligned}$$

Signature is the pair $(r, s)$. To **verify** $(r, s)$ on $m$ with public key $Q$:

$$\begin{aligned}
e &= \mathrm{SHA{\text -}256}(m)\ \text{truncated} \\
w &= s^{-1} \bmod n \\
u_1 &= ew \bmod n,\quad u_2 = rw \bmod n \\
(x_1, y_1) &= u_1 G + u_2 Q
\end{aligned}$$

The signature is valid iff $x_1 \equiv r \pmod{n}$. The freshly random $k$ per signature is critical: reusing $k$ across two signatures leaks $d$ algebraically (this is the bug that broke the PS3).

### HKDF-SHA256 (key derivation)

The raw ECDH secret is "random-ish" but not directly usable as an AES or HMAC key. HKDF turns it into uniform, key-sized chunks. Two stages:

**Extract** — concentrate the entropy:

$$\mathrm{PRK} = \mathrm{HMAC{\text -}SHA256}(\mathrm{salt},\ \mathrm{IKM})$$

In our case `IKM` is the ECDH shared secret and `salt` is the concatenation of the two ephemeral public keys (sorted, so both sides agree on the order).

**Expand** — stretch to whatever length you need:

$$\begin{aligned}
T_1 &= \mathrm{HMAC{\text -}SHA256}(\mathrm{PRK},\ \mathrm{info} \,\|\, \texttt{0x01}) \\
T_i &= \mathrm{HMAC{\text -}SHA256}(\mathrm{PRK},\ T_{i-1} \,\|\, \mathrm{info} \,\|\, i) \quad \text{for } i \ge 2 \\
\mathrm{OKM} &= T_1 \,\|\, T_2 \,\|\, \cdots\ \text{truncated to length } L
\end{aligned}$$

We ask for $L = 96$ bytes and slice them into four pieces:

$$\underbrace{16\text{ B}}_{k^{\text{enc}}_1}\ \underbrace{32\text{ B}}_{k^{\text{mac}}_1}\ \underbrace{16\text{ B}}_{k^{\text{enc}}_2}\ \underbrace{32\text{ B}}_{k^{\text{mac}}_2}$$

The side whose ephemeral public key sorts smaller takes $(k^{\text{enc}}_1, k^{\text{mac}}_1)$ as its **send** keys; the other side takes the same pair as its **receive** keys. Each direction therefore has independent encryption and authentication keys.

### AES-128-CBC

Encryption with key $K$ (128 bits) and IV (128 bits, freshly random per message). The plaintext is split into 128-bit blocks $P_1, P_2, \ldots, P_n$ after PKCS#7 padding. Then

$$C_0 = \mathrm{IV}, \qquad C_i = \mathrm{AES}_K(P_i \oplus C_{i-1})$$

Decryption inverts each block:

$$P_i = \mathrm{AES}^{-1}_K(C_i) \oplus C_{i-1}$$

The fresh random IV is what makes encrypting the same plaintext twice yield two unrelated ciphertexts.

### HMAC-SHA256

For key $K$ and message $m$, with hash $H$ = SHA-256 and block size $B = 64$ bytes:

$$K' = \begin{cases} K & \text{if } |K| \le B \\ H(K) & \text{if } |K| > B \end{cases}$$

(zero-padded on the right to length $B$, in either case)

$$\mathrm{HMAC}(K, m) = H\bigl((K' \oplus \mathrm{opad}) \,\|\, H((K' \oplus \mathrm{ipad}) \,\|\, m)\bigr)$$

with $\mathrm{ipad} = \texttt{0x36}$ repeated and $\mathrm{opad} = \texttt{0x5c}$ repeated. The double hashing is what gives HMAC its security proof against length-extension and related attacks on the underlying Merkle–Damgård hash.

### The full record format

For each chat message $P$, the sender computes:

$$\begin{aligned}
\mathrm{IV} &\xleftarrow{\$} \{0,1\}^{128} \\
C &= \mathrm{AES{\text -}128{\text -}CBC}(k^{\text{enc}}_{\text{send}},\ \mathrm{IV},\ \mathrm{PKCS7}(P)) \\
T &= \mathrm{HMAC{\text -}SHA256}(k^{\text{mac}}_{\text{send}},\ \mathrm{IV} \,\|\, C)
\end{aligned}$$

and transmits $\mathrm{IV} \,\|\, C \,\|\, T$ (with a 4-byte big-endian length prefix for TCP framing). The receiver runs:

$$\begin{aligned}
\text{abort if}\ \ &\mathrm{HMAC{\text -}SHA256}(k^{\text{mac}}_{\text{recv}},\ \mathrm{IV} \,\|\, C) \neq T \\
P &= \mathrm{PKCS7}^{-1}\bigl(\mathrm{AES{\text -}128{\text -}CBC}^{-1}(k^{\text{enc}}_{\text{recv}},\ \mathrm{IV},\ C)\bigr)
\end{aligned}$$

The MAC check is constant-time. The decryption only runs if the MAC is valid.

## What this protocol actually gives you, and what it doesn't

It's worth being honest about which security properties hold and which don't, because the answers depend on which primitive you're looking at.

**Confidentiality of chat messages.** Yes. AES-128-CBC under a key that only the two parties know. Anyone passively recording the wire sees `IV ‖ C ‖ T`, all of which look uniformly random. Without the encryption key, recovering $P$ requires breaking AES-128.

**Integrity of chat messages.** Yes. The HMAC-SHA256 tag covers both the IV and the ciphertext, so any single-bit flip anywhere in the record causes the tag check to fail. The receiver aborts before decrypting; the tampered message is dropped.

**Authentication of the channel.** Yes. The handshake signs each ephemeral DH public key with the long-term ECDSA key, and the peer verifies with a public key it already trusts (from the manual key swap). A man-in-the-middle who tries to substitute their own ephemeral DH value can't produce a valid signature, so the handshake aborts. Once the handshake completes, both sides know they're talking to whoever owns the long-term ECDSA private keys they exchanged offline.

**Authentication of individual chat messages.** Yes, but symmetrically. The HMAC tag proves the message was produced by someone holding $k^{\text{mac}}_{\text{send}}$, and that key only exists on the two endpoints. So the receiver knows the message came from the legitimate peer (and not from an active attacker on the wire).

**Forward secrecy.** Yes. The DH keys are ephemeral — generated per session, used for the handshake, then dropped. If the long-term ECDSA private keys leak tomorrow, an attacker who recorded today's traffic still can't decrypt it, because the ECDH shared secret would require either $d_A^{\text{eph}}$ or $d_B^{\text{eph}}$, neither of which exists anymore.

**Non-repudiation.** Mostly **no**, and that's actually a feature of how we built it. The chat messages themselves are protected by an HMAC, which is a *symmetric* primitive — both Alice and Bob hold the same MAC key, so either of them could have produced any given tag. Bob can verify a message came from someone with the key (which proves to him it was Alice), but he can't prove that to a third party, because he could have forged it himself. This is called "deniability" and it's deliberately the property of protocols like Signal and OTR. The handshake itself does involve ECDSA signatures, which *are* non-repudiable (a third party can verify a signature against Alice's public key) — but those signatures only cover ephemeral DH public keys, not chat content. So: a third party can prove "Alice did a key exchange at some point," but cannot prove "Alice sent message $X$."

**Replay protection across sessions.** Yes. Each new session derives fresh keys from new ephemeral DH values, salted with both ephemeral pubs. A captured message from session 1 won't decrypt under session 2's keys.

**Replay protection within a session.** **No.** We don't include sequence numbers or timestamps inside the authenticated payload. An on-path attacker who captures a valid record could in principle re-inject it later in the same session, and the receiver would happily verify and print it again. For a real production protocol you'd add a monotonically increasing message counter under the MAC; for this assignment, it's a known and explicit gap.

**Resistance to known weaknesses of the chosen primitives.**

- *CBC padding-oracle attacks:* Encrypt-then-MAC neutralises them. The padding is only ever inspected after a valid MAC, so an attacker can't iterate ciphertexts and use padding-error responses as a distinguisher.
- *Key reuse across purposes:* Avoided. HKDF gives us four distinct keys; AES never sees the HMAC key and vice versa.
- *Direction reuse:* Avoided. Each direction has its own pair of keys, so a recorded outgoing message can't be replayed back as a valid incoming one.
- *Timing attacks on MAC verification:* Avoided. PyCA's `HMAC.verify` does a constant-time comparison.
- *IV reuse:* Avoided. A fresh 128-bit random IV per message; collision probability is negligible.
- *Nonce/$k$ reuse in ECDSA:* Avoided. PyCA generates $k$ via RFC 6979 (deterministic from $d$ and $m$), so two distinct messages necessarily get distinct $k$.

**Threats explicitly outside scope.** Endpoint compromise (keylogger, malware on either machine), physical access to either `keys/*_priv.pem`, social-engineering during the public-key swap (someone tricks you into accepting their pubkey instead of your peer's — no PKI here, the trust is "I copied this file from you in person"), traffic analysis (an observer learns *that* you're chatting and roughly *how much*, even without learning *what*), and denial-of-service (anyone can drop your TCP connection). None of these are problems the assignment asks us to solve.


## CLI reference

From `Using Library of PyCA/02 Messenger (Handshaking)/Server/`:
```
python alt_run_server.py
```


From `Using Library of PyCA/02 Messenger (Handshaking)/Client/`:
```
python alt_run_client.py client <server_ip>
```

