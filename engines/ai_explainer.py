"""
AI Threat Explanation Engine.
Uses local heuristic templates + optionally a local LLM (Ollama/llama.cpp).
Falls back gracefully to template-based explanations if no LLM is available.
"""
import json
from engines.mitre_mapper import get_technique

EXPLANATION_TEMPLATES = {
    "arp_spoof": (
        "Device {ip} is sending ARP replies claiming to own {target_ip}'s MAC address. "
        "This is a classic ARP cache poisoning pattern used to intercept traffic "
        "(MITRE {mitre_id}: {mitre_name}). "
        "Evidence: {evidence}. Risk: All traffic to/from {target_ip} may be intercepted."
    ),
    "unknown_device": (
        "A new device with MAC {mac} joined the network. "
        "The vendor OUI is {vendor}. No prior history exists in baseline. "
        "Threat score elevated due to: unknown origin, {port_count} open ports detected, "
        "behaviour deviates from baseline by {sigma:.1f}σ."
    ),
    "dangerous_port": (
        "Port {port} on {ip} is associated with {service}. "
        "This port is commonly used by {risk_reason}. "
        "Immediate investigation recommended."
    ),
    "port_scan": (
        "Device {ip} has probed {port_count} ports on the network within {time_window}s. "
        "This matches the profile of automated network reconnaissance "
        "(MITRE {mitre_id}: {mitre_name})."
    ),
}

DANGEROUS_PORT_REASONS = {
    4444:  "Metasploit reverse shells",
    5900:  "VNC remote access (often unauthenticated)",
    3389:  "RDP – brute-force target",
    23:    "Telnet – plaintext credentials",
    6667:  "IRC – historically used by botnets",
    31337: "Back Orifice malware",
}

def generate_explanation(alert_type: str, context: dict) -> dict:
    """
    Returns dict with:
      - explanation: human-readable string
      - confidence: 0.0–1.0
      - threat_score: 0–100
      - evidence_summary: list of bullet strings
    """
    technique = get_technique(alert_type)
    ctx = {**context, "mitre_id": technique["id"], "mitre_name": technique["name"]}

    template = EXPLANATION_TEMPLATES.get(alert_type, "Suspicious activity detected on {ip}.")
    try:
        explanation = template.format(**ctx)
    except KeyError:
        explanation = f"Threat detected: {alert_type}. Context: {json.dumps(context)}"

    score = _calculate_threat_score(alert_type, context)
    confidence = _calculate_confidence(alert_type, context)
    evidence = _build_evidence(alert_type, context)

    return {
        "explanation": explanation,
        "threat_score": score,
        "confidence": confidence,
        "evidence_summary": evidence,
        "mitre": technique,
    }

def _calculate_threat_score(alert_type: str, ctx: dict) -> float:
    base_scores = {
        "arp_spoof": 85, "mitm": 90, "dangerous_port": 70,
        "port_scan": 65, "unknown_device": 50, "mac_spoof": 80,
        "beaconing": 75, "data_exfil": 95,
    }
    score = base_scores.get(alert_type, 50)
    if ctx.get("is_tor"):         score = min(100, score + 15)
    if ctx.get("abuse_score", 0) > 50: score = min(100, score + 10)
    if ctx.get("cve_critical"):   score = min(100, score + 10)
    sigma = ctx.get("sigma", 0)
    if sigma > 3:                 score = min(100, score + 5)
    return round(score, 1)

def _calculate_confidence(alert_type: str, ctx: dict) -> float:
    conf = 0.6
    if ctx.get("packet_count", 0) > 10: conf += 0.1
    if ctx.get("repeated"):             conf += 0.15
    if ctx.get("multiple_indicators"):  conf += 0.1
    return round(min(1.0, conf), 2)

def _build_evidence(alert_type: str, ctx: dict) -> list:
    ev = []
    if ctx.get("vendor") == "Unknown":      ev.append("Unknown vendor (OUI not in database)")
    if ctx.get("dangerous_ports"):          ev.append(f"Dangerous ports: {ctx['dangerous_ports']}")
    if ctx.get("sigma", 0) > 2.0:          ev.append(f"Traffic anomaly: {ctx['sigma']:.1f}σ above baseline")
    if ctx.get("is_tor"):                   ev.append("Source IP matches TOR exit node list")
    if ctx.get("abuse_score", 0) > 0:      ev.append(f"AbuseIPDB score: {ctx['abuse_score']}/100")
    if ctx.get("otx_pulses", 0) > 0:       ev.append(f"AlienVault OTX: {ctx['otx_pulses']} threat pulses")
    return ev if ev else ["Heuristic pattern match"]