import requests
from datetime import datetime, timedelta
from config import Config
from models.database import get_conn

def check_ip(ip: str) -> dict:
    """Check AbuseIPDB + OTX + TOR for an IP. Caches 24h."""
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM threat_intel_cache WHERE ip=? AND cached_at > datetime('now','-1 day')",
        (ip,)
    ).fetchone()
    if row:
        conn.close()
        return dict(row)

    result = {"ip": ip, "abuse_score": 0, "otx_pulses": 0,
              "is_tor": 0, "country": "", "city": "", "lat": 0.0, "lon": 0.0}

    # AbuseIPDB
    if Config.ABUSEIPDB_KEY:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key": Config.ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=5)
            d = r.json().get("data", {})
            result["abuse_score"] = d.get("abuseConfidenceScore", 0)
            result["country"]     = d.get("countryCode", "")
        except Exception:
            pass

    # AlienVault OTX
    if Config.OTX_API_KEY:
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": Config.OTX_API_KEY}, timeout=5)
            result["otx_pulses"] = r.json().get("pulse_info", {}).get("count", 0)
        except Exception:
            pass

    # TOR exit nodes
    try:
        with open(Config.TOR_NODES_FILE) as f:
            tor_nodes = set(line.strip() for line in f)
        result["is_tor"] = 1 if ip in tor_nodes else 0
    except Exception:
        pass

    # Geolocation
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        geo = r.json()
        result.update({"lat": geo.get("lat",0), "lon": geo.get("lon",0),
                        "city": geo.get("city",""), "country": geo.get("countryCode","")})
    except Exception:
        pass

    conn.execute(
        """INSERT OR REPLACE INTO threat_intel_cache
           (ip, abuse_score, otx_pulses, is_tor, country, city, lat, lon, cached_at)
           VALUES (?,?,?,?,?,?,?,?,datetime('now'))""",
        tuple(result.values()) + ()
    )
    conn.commit()
    conn.close()
    return result