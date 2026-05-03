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
        
        print(self.host)


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
            

        # Start send and receive loops
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
                    #self.running = False
                    break
                    
                message = data.decode()
                if message.strip().lower() == "exit":
                    print("\n[Peer exited]")
                    #self.running = False
                    break
                print(f"\n[Peer]: {message}")
            except Exception as e:
                print(f"[Receive error]: {e}")
                self.running = False
                break                           
          

    def _send_loop(self):
        """Reads user input and sends it as plain text to the peer."""
        while True:
            try:
                msg = input("You: ").strip()
                if msg.lower() == "exit":
                    self.conn.sendall(msg.encode())
                    #self.running = False
                    break
                self.conn.sendall(msg.encode())
            except Exception as e:
                print(f"[Send error]: {e}")
                self.running = False
                break

        self.conn.close()
        self.sock.close()
        print("[*] Connection closed.")

		    

            

