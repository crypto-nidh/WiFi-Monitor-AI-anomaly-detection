"""Geolocation helper using external IP API."""

import requests


def lookup_ip(ip_address):
    """Return latitude/longitude for an IP address."""
    response = requests.get(f'http://ip-api.com/json/{ip_address}')
    if response.ok:
        data = response.json()
        return {'lat': data.get('lat'), 'lon': data.get('lon'), 'city': data.get('city')}
    return None
