# Maps detection types to MITRE ATT&CK techniques
MITRE_MAP = {
    "arp_spoof":      {"id": "T1557", "name": "Adversary-in-the-Middle",
                       "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1557/"},
    "mitm":           {"id": "T1557.002", "name": "ARP Cache Poisoning",
                       "tactic": "Collection"},
    "port_scan":      {"id": "T1046",  "name": "Network Service Discovery",
                       "tactic": "Discovery"},
    "mac_spoof":      {"id": "T1036",  "name": "Masquerading",
                       "tactic": "Defense Evasion"},
    "dns_anomaly":    {"id": "T1071.004","name": "DNS C2",
                       "tactic": "Command and Control"},
    "beaconing":      {"id": "T1071",  "name": "Application Layer Protocol",
                       "tactic": "Command and Control"},
    "data_exfil":     {"id": "T1048",  "name": "Exfiltration Over Alt Protocol",
                       "tactic": "Exfiltration"},
    "dangerous_port": {"id": "T1049",  "name": "System Network Connections Discovery",
                       "tactic": "Discovery"},
    "rogue_device":   {"id": "T1200",  "name": "Hardware Additions",
                       "tactic": "Initial Access"},
}

def get_technique(detection_type: str) -> dict:
    return MITRE_MAP.get(detection_type, {"id": "T0000", "name": "Unknown", "tactic": "Unknown"})