from models.database import get_conn

def compute_network_score() -> dict:
    """
    Returns overall 0–100 security score and per-category sub-scores.
    Lower score = more threats.
    """
    conn = get_conn()

    # Category: Vulnerabilities (0–25)
    crit = conn.execute(
        "SELECT COUNT(*) as n FROM cve_findings WHERE severity='Critical'").fetchone()["n"]
    high = conn.execute(
        "SELECT COUNT(*) as n FROM cve_findings WHERE severity='High'").fetchone()["n"]
    vuln_penalty = min(25, crit * 8 + high * 3)
    vuln_score = 25 - vuln_penalty

    # Category: Device Trust (0–25)
    total = conn.execute("SELECT COUNT(*) as n FROM devices").fetchone()["n"] or 1
    untrusted = conn.execute(
        "SELECT COUNT(*) as n FROM devices WHERE trust_score < 40").fetchone()["n"]
    trust_score = max(0, 25 - int((untrusted / total) * 25))

    # Category: Exposure (0–25)  — dangerous ports open
    dangerous = conn.execute(
        "SELECT COUNT(*) as n FROM open_ports WHERE port IN (22,23,3389,4444,5900,6667,8080)"
    ).fetchone()["n"]
    exposure_score = max(0, 25 - min(25, dangerous * 5))

    # Category: Threat Activity (0–25) — recent alerts in last hour
    recent = conn.execute(
        "SELECT COUNT(*) as n FROM alerts WHERE created_at > datetime('now','-1 hour')"
    ).fetchone()["n"]
    activity_score = max(0, 25 - min(25, recent * 5))

    conn.close()
    total_score = vuln_score + trust_score + exposure_score + activity_score
    return {
        "total": total_score,
        "vulnerability": vuln_score,
        "device_trust": trust_score,
        "exposure": exposure_score,
        "threat_activity": activity_score,
        "grade": _score_to_grade(total_score)
    }

def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"