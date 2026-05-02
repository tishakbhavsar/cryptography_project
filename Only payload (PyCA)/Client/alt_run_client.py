import sys
import socket
from peer import Peer

def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('8.8.8.8', 80))
        ip = sock.getsockname()[0]
        name = socket.gethostname()
    except Exception:
        ip = '127.0.0.1'
        name = 'Guest'
    finally:
        sock.close()
        
    #ip = '100.90.31.3'
    #name = 'Tapas'
    return ip, name

def main():
    if len(sys.argv) < 3 or sys.argv[1].lower() != 'client':
            print("Usage: python3 alt_run_client.py client <server_ip>")
            return

    host_ip, host_name = get_local_ip()
    print(f"[INFO] Detected local IP: {host_ip}")
    print(f"[INFO] Hostname: {host_name}")

    server_ip = sys.argv[2]
    peer = Peer(is_server=False, host=server_ip)
    peer.start()

if __name__ == "__main__":
    main()

