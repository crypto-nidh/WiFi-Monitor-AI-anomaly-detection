"""ARP scanner and network discovery utilities."""

from scapy.all import ARP, Ether, srp


def arp_scan(network):
    """Perform an ARP scan for the given network range."""
    arp = ARP(pdst=network)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)[0]
    return [{'ip': sent.psrc, 'mac': received.hwsrc} for sent, received in result]
