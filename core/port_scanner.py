"""Port scanning and service banner collection."""

import socket


def scan_ports(host, ports):
    """Scan ports and return open ports."""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
    return open_ports
