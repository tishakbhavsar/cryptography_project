from crypto_utils import load_public_key  # Make sure this function exists
from crypto_utils import *
import socket
import threading


class Peer:
    def __init__(self, is_server, host='127.0.0.1', port=5002): # port=0 means OS picks
        # Initialize a TCP socket
        self.sock = socket.socket()
        
        # True if this peer should act as a server
        self.is_server = is_server
        
        #self.running = True
        
        # IP address and port to bind or connect to
        self.host = host
        self.port = port           
        #print(self.host)
        
        # Generate signing keypair and ephemeral keypair for key exchange
        self.sign_priv, self.sign_pub = generate_signing_keypair()
        self.eph_private_key, self.eph_public_key = generate_ephemeral_keypair()

        # To store AES and HMAC keys after handshake
        self.aes_key = None
        self.hmac_key = None

        # To store peer's public key for signature verification
        #self.peer_public_key = None
        
        


    def start(self):
        """Starts the peer in either server or client mode, performs handshake, and launches communication threads."""
        if self.is_server:
            # Server binds and listens for one connection
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            print("[*] Waiting for connection...")
            conn, _ = self.sock.accept()
            
            #client_ip, client_port = conn.getpeername()
            #print(f"Client connected from IP: {client_ip}, Port: {client_port}")
            self.conn = conn  # Store the accepted connection
            
        else:
            # Client connects to the server
            self.sock.connect((self.host, self.port))
            
            #client_ip, client_port = self.sock.getpeername()
            #print(f"Client connected from IP: {client_ip}, Port: {client_port}")
            
            self.conn = self.sock  # Use socket itself for client
        
        #Start handshaking protocol for session key    
        self._handshake()

        # Start send and receive loops
        self._start_threads()
        
        
    def _handshake(self):
        """Exchanges public keys and derives the session key."""
        print("[*] Starting handshake...")
        # simple length-prefixed send/recv helpers
        def send_bytes(conn, data: bytes):
            conn.sendall(len(data).to_bytes(4, 'big') + data)

        def recv_bytes(conn):
            hdr = conn.recv(4)
            if not hdr:
                raise ConnectionError("No header")
            length = int.from_bytes(hdr, 'big')
            buf = b''
            while len(buf) < length:
                chunk = conn.recv(length - len(buf))
                if not chunk:
                    raise ConnectionError("Unexpected EOF")
                buf += chunk
            return buf

        # Server receives client's signing pub, ephemeral pub, signature first
        client_sign_pub = recv_bytes(self.conn)
        client_eph = recv_bytes(self.conn)
        client_sig = recv_bytes(self.conn)

        # Verify client's signature
        if not verify_signature(client_sign_pub, client_eph, client_sig):
            raise Exception("Client signature verification failed")

        # Send server's signing pub, ephemeral pub, signature
        send_bytes(self.conn, self.sign_pub)
        send_bytes(self.conn, self.eph_public_key)
        send_bytes(self.conn, sign_data(self.sign_priv, self.eph_public_key))

        # Derive AES and HMAC keys
        self.aes_key, self.hmac_key = perform_key_exchange(self.eph_private_key, client_eph)

        print("[+] Handshake complete. Secure session established.")


    def _start_threads(self):
        """Starts a background thread for receiving and enters sending loop in the main thread."""
        # Start receiving in a daemon thread
        threading.Thread(target=self._receive_loop, daemon=True).start()
        print("I'm ready")
        
        # Start sending in the main thread
        self._send_loop()
    
    def _receive_loop(self):
        """Receives and prints plain text messages from the peer."""
        def recv_bytes(conn):
            hdr = conn.recv(4)
            if not hdr:
                return None
            length = int.from_bytes(hdr, 'big')
            buf = b''
            while len(buf) < length:
                chunk = conn.recv(length - len(buf))
                if not chunk:
                    return None
                buf += chunk
            return buf

        while True:
            try:
                blob = recv_bytes(self.conn)
                if not blob:
                    print("\n[Peer disconnected]")
                    break
                if self.aes_key is None:
                    print("[!] No session keys established")
                    break
                try:
                    plaintext = verify_and_decrypt(blob, self.aes_key, self.hmac_key)
                except Exception as e:
                    print(f"[Decrypt error]: {e}")
                    break
                message = plaintext.decode()
                if message.strip().lower() == "exit":
                    print("\n[Peer exited]")
                    break
                print(f"\n[Peer]: {message}")
            except Exception as e:
                print(f"[Receive error]: {e}")
                break                           
          

    def _send_loop(self):
        """Reads user input and sends it as plain text to the peer."""
        def send_bytes(conn, data: bytes):
            conn.sendall(len(data).to_bytes(4, 'big') + data)

        while True:
            try:
                msg = input("You: ").strip()
                if msg.lower() == "exit":
                    if self.aes_key:
                        blob = encrypt_then_mac(msg.encode(), self.aes_key, self.hmac_key)
                        send_bytes(self.conn, blob)
                    else:
                        self.conn.sendall(msg.encode())
                    break
                if self.aes_key is None:
                    print("[!] No session keys established")
                    break
                blob = encrypt_then_mac(msg.encode(), self.aes_key, self.hmac_key)
                send_bytes(self.conn, blob)
            except Exception as e:
                print(f"[Send error]: {e}")
                break

        #self.conn.close()
        self.sock.close()
        print("[*] Connection closed.")

		    

            

