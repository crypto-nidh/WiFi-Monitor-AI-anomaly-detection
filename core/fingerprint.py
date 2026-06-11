"""Device and OS fingerprinting helpers."""

def fingerprint_device(mac_address, vendor_db=None):
    """Return device fingerprint metadata from a MAC address."""
    vendor = None
    if vendor_db and mac_address:
        prefix = mac_address.upper().replace(':', '')[:6]
        vendor = vendor_db.get(prefix)
    return {'mac': mac_address, 'vendor': vendor}
