import sys
from peer import Peer
import socket


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
    #ip = '100.83.89.68'
    #name = 'Fermat'

    return ip, name


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'server'
    is_server = mode.lower() == 'server'

    # Automatically get the IP address of the machine
    host_ip, host_name = get_local_ip()
    
    # Allow override with explicit IP (e.g., Tailscale IP as 2nd argument)
    if len(sys.argv) > 2:
        host_ip = sys.argv[2]
    
    print(f"[INFO] Detected IP: {host_ip}")
    print(f"[INFO] Hostname: {host_name}")

    # For Tailscale, bind to 0.0.0.0 (all interfaces) instead of specific IP
    bind_host = '0.0.0.0'
    
    # Create peer with bind address
    peer = Peer(is_server, host=bind_host)

    peer.start()


if __name__ == "__main__":
    main()

