import os

class Config:
    # API Keys
    ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_KEY", "")
    OTX_API_KEY      = os.getenv("OTX_API_KEY", "")
    TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN", "")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
    NVD_API_KEY      = os.getenv("NVD_API_KEY", "")   # optional, raises rate limit

    # Network
    SCAN_INTERVAL    = int(os.getenv("SCAN_INTERVAL", 30))
    NETWORK_RANGE    = os.getenv("NETWORK_RANGE", "192.168.1.0/24")
    INTERFACE        = os.getenv("INTERFACE", "wlan0")

    # Thresholds
    Z_SCORE_THRESHOLD     = float(os.getenv("Z_SCORE_THRESHOLD", 2.5))
    THREAT_SCORE_ALERT    = float(os.getenv("THREAT_SCORE_ALERT", 70.0))
    PORT_SCAN_THRESHOLD   = int(os.getenv("PORT_SCAN_THRESHOLD", 10))  # ports/min

    # Dangerous ports list
    DANGEROUS_PORTS = {
        22, 23, 3389, 4444, 5900, 6667, 8080,
        1337, 31337, 12345, 27374
    }

    # Paths
    DB_PATH          = os.getenv("DB_PATH", "data/cve_cache.db")
    MITRE_JSON       = "data/mitre_techniques.json"
    TOR_NODES_FILE   = "data/tor_exit_nodes.txt"