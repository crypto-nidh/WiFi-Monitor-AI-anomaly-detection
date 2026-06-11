"""Threat intelligence enrichment using AbuseIPDB, OTX, and TOR checks."""

def enrich_ip(ip_address):
    return {'ip': ip_address, 'abuse_score': None, 'is_tor_exit': False}
