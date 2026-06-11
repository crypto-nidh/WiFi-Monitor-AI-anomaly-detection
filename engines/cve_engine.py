import requests, json
from config import Config
from models.database import get_conn

# Service → common CVE keywords lookup (offline fallback)
SERVICE_CVE_MAP = {
    "Apache/2.4.49": [
        {"cve_id": "CVE-2021-41773", "cvss": 9.8, "severity": "Critical",
         "description": "Path traversal and RCE in Apache 2.4.49",
         "remediation": "Upgrade Apache to 2.4.51 or later immediately.",
         "exploit_likelihood": "High – public exploits available"}
    ],
    "OpenSSH/7.2": [
        {"cve_id": "CVE-2016-6210", "cvss": 5.3, "severity": "Medium",
         "description": "User enumeration via timing side-channel",
         "remediation": "Upgrade OpenSSH to 8.x+",
         "exploit_likelihood": "Low – requires local network access"}
    ],
}

def query_nvd(service: str, version: str) -> list:
    """Query NVD API v2 for CVEs matching a keyword."""
    keyword = f"{service} {version}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    if Config.NVD_API_KEY:
        headers["apiKey"] = Config.NVD_API_KEY
    try:
        r = requests.get(url, params={"keywordSearch": keyword, "resultsPerPage": 5},
                         headers=headers, timeout=10)
        data = r.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cvss = 0.0
            try:
                metrics = cve.get("metrics", {})
                cvss = (metrics.get("cvssMetricV31") or
                        metrics.get("cvssMetricV30") or
                        metrics.get("cvssMetricV2") or [{}])[0]
                cvss = cvss.get("cvssData", {}).get("baseScore", 0.0)
            except Exception:
                pass
            severity = _cvss_to_severity(cvss)
            results.append({
                "cve_id": cve["id"],
                "cvss": cvss,
                "severity": severity,
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "remediation": "Check vendor advisory for patch.",
                "exploit_likelihood": "Unknown"
            })
        return results
    except Exception:
        return SERVICE_CVE_MAP.get(f"{service}/{version}", [])

def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"

def analyze_device_cves(mac: str, ports: list) -> list:
    """Given list of {port, service, version}, find and store CVEs."""
    conn = get_conn()
    findings = []
    for p in ports:
        cves = query_nvd(p.get("service",""), p.get("version",""))
        for cve in cves:
            conn.execute(
                """INSERT OR IGNORE INTO cve_findings
                   (device_mac, port, cve_id, cvss_score, severity,
                    description, remediation, exploit_likelihood)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (mac, p["port"], cve["cve_id"], cve["cvss"],
                 cve["severity"], cve["description"],
                 cve["remediation"], cve["exploit_likelihood"])
            )
            findings.append({**cve, "port": p["port"], "mac": mac})
    conn.commit()
    conn.close()
    return findings