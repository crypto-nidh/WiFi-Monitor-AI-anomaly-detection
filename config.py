import os

FLASK_ENV = os.getenv('FLASK_ENV', 'development')
SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')

ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
OTX_API_KEY = os.getenv('OTX_API_KEY', '')

ARP_SCAN_TIMEOUT = int(os.getenv('ARP_SCAN_TIMEOUT', '5'))
THREAT_SCORE_THRESHOLD = float(os.getenv('THREAT_SCORE_THRESHOLD', '70.0'))
