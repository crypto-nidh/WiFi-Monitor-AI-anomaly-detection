"""Deep packet inspection metadata analysis."""

def inspect_packet(packet):
    """Analyze packet metadata without decryption."""
    return {
        'src': packet.get('src'),
        'dst': packet.get('dst'),
        'protocol': packet.get('protocol'),
    }
