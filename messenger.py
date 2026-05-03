"""Run the secure messenger as either server or client.

Usage:
    python messenger.py server [host] [port]
    python messenger.py client <host> [port]

Examples:
    # Same machine, two terminals:
    python messenger.py server 127.0.0.1
    python messenger.py client 127.0.0.1

    # Two machines on a LAN — server prints its IP; client connects to it:
    python messenger.py server                 # binds to detected LAN IP
    python messenger.py client 10.1.57.116
"""
import socket
import sys

from peer import Peer

DEFAULT_PORT = 5002


def detect_lan_ip():
    """Best-effort LAN IP. Falls back to loopback if offline."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def usage_and_exit():
    print(__doc__)
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        usage_and_exit()

    mode = sys.argv[1].lower()
    if mode not in ("server", "client"):
        usage_and_exit()

    if mode == "server":
        host = sys.argv[2] if len(sys.argv) > 2 else detect_lan_ip()
        port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
        print(f"[INFO] Server host: {host}  port: {port}")
    else:
        if len(sys.argv) < 3:
            print("client mode requires <host>")
            usage_and_exit()
        host = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
        print(f"[INFO] Client connecting to {host}:{port}")

    Peer(is_server=(mode == "server"), host=host, port=port).start()


if __name__ == "__main__":
    main()
