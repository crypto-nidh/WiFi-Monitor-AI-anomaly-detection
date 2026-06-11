"""
AI Security Copilot — answers natural-language questions about the
current network state using live DB data + heuristic knowledge.
Optionally integrates a local Ollama endpoint.
"""
import re
from models.database import get_conn
from engines.cve_engine import analyze_device_cves
from engines.scoring_engine import compute_network_score

def copilot_query(question: str) -> str:
    q = question.lower()
    
    if "highest risk" in q or "most dangerous" in q:
        return _highest_risk_device()
    if "score" in q or "how safe" in q:
        return _explain_score()
    if re.search(r"cve-\d{4}-\d+", q):
        cve_id = re.search(r"(cve-\d{4}-\d+)", q, re.I).group(1).upper()
        return _explain_cve(cve_id)
    if "suspicious" in q and re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q):
        ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q).group(0)
        return _explain_device(ip=ip)
    if "alert" in q or "threat" in q:
        return _latest_alerts_summary()
    
    return ("I can answer: 'Why is [IP] suspicious?', 'What does CVE-XXXX-XXXXX mean?', "
            "'Show highest risk device', 'What is the network score?', "
            "'Summarise latest alerts'.")

def _highest_risk_device() -> str:
    conn = get_conn()
    row = conn.execute(
        """SELECT d.ip, d.mac, d.hostname, d.vendor, d.trust_score,
                  COUNT(a.id) as alert_count
           FROM devices d LEFT JOIN alerts a ON a.device_mac = d.mac
           GROUP BY d.mac ORDER BY alert_count DESC, d.trust_score ASC LIMIT 1"""
    ).fetchone()
    conn.close()
    if not row:
        return "No devices found in the database."
    return (f"Highest risk device: {row['ip']} ({row['hostname'] or 'no hostname'})\n"
            f"Vendor: {row['vendor']} | Trust score: {row['trust_score']:.0f}/100\n"
            f"Total alerts generated: {row['alert_count']}")

def _explain_score() -> str:
    s = compute_network_score()
    return (f"Network Security Score: {s['total']}/100 (Grade: {s['grade']})\n"
            f"• Vulnerability score: {s['vulnerability']}/25\n"
            f"• Device trust: {s['device_trust']}/25\n"
            f"• Exposure: {s['exposure']}/25\n"
            f"• Threat activity (last hour): {s['threat_activity']}/25")

def _explain_cve(cve_id: str) -> str:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM cve_findings WHERE cve_id=? LIMIT 1", (cve_id,)
    ).fetchone()
    conn.close()
    if not row:
        return f"{cve_id} is not currently in the local findings. Check https://nvd.nist.gov/vuln/detail/{cve_id}"
    return (f"{cve_id} — {row['severity']} (CVSS {row['cvss_score']})\n"
            f"{row['description']}\n"
            f"Remediation: {row['remediation']}\n"
            f"Exploit likelihood: {row['exploit_likelihood']}")

def _explain_device(ip: str) -> str:
    conn = get_conn()
    d = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
    if not d:
        conn.close()
        return f"No device found with IP {ip}."
    alerts = conn.execute(
        "SELECT alert_type, threat_score, explanation FROM alerts WHERE device_mac=? ORDER BY created_at DESC LIMIT 3",
        (d["mac"],)
    ).fetchall()
    conn.close()
    lines = [f"Device {ip} ({d['hostname'] or 'unknown'}) – {d['vendor']}",
             f"OS: {d['os_guess']} | Type: {d['device_type']} | Trust: {d['trust_score']:.0f}/100"]
    if alerts:
        lines.append("Recent alerts:")
        for a in alerts:
            lines.append(f"  [{a['alert_type']}] Score {a['threat_score']}: {a['explanation'][:120]}...")
    else:
        lines.append("No alerts generated for this device.")
    return "\n".join(lines)

def _latest_alerts_summary() -> str:
    conn = get_conn()
    rows = conn.execute(
        "SELECT alert_type, COUNT(*) as n FROM alerts WHERE created_at > datetime('now','-1 hour') GROUP BY alert_type"
    ).fetchall()
    conn.close()
    if not rows:
        return "No alerts in the past hour. Network looks quiet."
    summary = "Alerts (last hour):\n" + "\n".join(f"  {r['alert_type']}: {r['n']}" for r in rows)
    return summary