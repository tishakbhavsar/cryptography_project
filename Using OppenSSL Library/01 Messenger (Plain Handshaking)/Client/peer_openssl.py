import socket
import threading
from openssl import *

class Peer:
    def __init__(self, is_server, host='127.0.0.1', port=5001):
        # Create a TCP socket (SOCK_STREAM ensures reliable, connection-oriented delivery)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        
        # True if this peer should act as a server
        self.is_server = is_server

        # IP address and port to bind or connect to
        self.host = host
        self.port = port

        # Placeholder for peer connection
        self.conn = None
        
        # Placeholder for session key
        self.session_key = None

        
     # ---------------------------------------- -------------------------
	 # ------------------------- Handshake Phase ------------------------
     # ---------------------------------------- ------------------------- 

    def _recv_full_pem(self):
	    """Receives the complete PEM public key from the peer."""
	    buffer = b""
	    while b"<<ENDKEY>>" not in buffer:
	        chunk = self.conn.recv(512)
	        print(f"chunk is: {chunk}")
	        if not chunk:
	            break
	        buffer += chunk
	    print(f"buffer is: {buffer}")
	    return buffer
    
            

    def _handshake(self):
        """Exchanges public keys and derives the session key."""
        print("[*] Starting handshake...")

        if self.is_server:
        	# 1. Receive peer's public key
            peer_pub_bytes = self._recv_full_pem()
            
            # 2. Generate and send this peer's public key
            pub_bytes = generate_ephemeral_keypair(self.is_server)
            #adding an end key marker
            pub_bytes += b"<<ENDKEY>>"
            self.conn.sendall(pub_bytes)
        else:
        	# 1. Send this peer's public key
            pub_bytes = generate_ephemeral_keypair(self.is_server)
            #adding an end key marker
            pub_bytes += b"<<ENDKEY>>"
            self.conn.sendall(pub_bytes)
            
            # 2. Receive peer's public key
            peer_pub_bytes = self._recv_full_pem()
            

		# 3. Derive session key
        self.session_key = perform_key_exchange(peer_pub_bytes, self.is_server) 
        print("[+] Handshake complete. Secure session established.")
        print(f"The session key is: {self.session_key}")
        
        
	# ---------------------------------------- -------------------------
 	# ------------------------- Connection Phase -----------------------
 	# ---------------------------------------- -------------------------
 	
    def start(self):
        """Starts the peer in either server or client mode and performs the handshake."""
        if self.is_server:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            print("[*] Waiting for connection...")
            conn, _ = self.sock.accept()
            self.conn = conn
        else:
            self.sock.connect((self.host, self.port))
            self.conn = self.sock

		# Perform key exchange handshake
        self._handshake()
        
        # Start concurrent send/receive loops
        self._start_threads()

    def _start_threads(self):
        """Starts a background thread for receiving and enters sending loop in the main thread."""
        # Start receiving in a daemon thread
        threading.Thread(target=self._receive_loop, daemon=True).start()
        print("I'm ready")
        
        # Start sending in the main thread
        self._send_loop()

    
    def _receive_loop(self):
        """Receives and prints plain text messages from the peer."""
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    print("\n[Peer disconnected]")
                    break
                message = data.decode()
                if message.strip().lower() == "exit":
                    print("\n[Peer exited]")
                    break
                print(f"\n[Peer]: {message}")
            except Exception as e:
                print(f"[Receive error]: {e}")
                break                           
          

    def _send_loop(self):
        """Reads user input and sends it as plain text to the peer."""
        while True:
            try:
                msg = input("You: ").strip()
                if msg.lower() == "exit":
                    self.conn.sendall(msg.encode())
                    break
                self.conn.sendall(msg.encode())
            except Exception as e:
                print(f"[Send error]: {e}")
                break

        self.conn.close()
        self.sock.close()
        print("[*] Connection closed.")

		    

            

