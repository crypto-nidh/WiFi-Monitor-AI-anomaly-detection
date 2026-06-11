"""Port, service, and CVE lookup with CVSS scoring."""

def lookup_cve(service_name):
    """Return CVE metadata for a service."""
    return {'service': service_name, 'cves': []}
