import sys
from peer_openssl import Peer
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
    print(f"[INFO] Detected IP: {host_ip}")
    print(f"[INFO] Hostname: {host_name}")

    # Create peer with detected IP
    peer = Peer(is_server, host=host_ip)

    peer.start()


if __name__ == "__main__":
    main()

