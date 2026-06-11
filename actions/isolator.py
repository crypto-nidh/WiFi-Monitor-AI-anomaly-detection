"""
Device isolation via iptables.
WARNING: Run with root/sudo. Test in a safe environment first.
Provides block (drop all traffic) and quarantine (allow DNS only) modes.
"""
import subprocess
from models.database import get_conn, insert_event

def _run(cmd: list) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0, result.stderr
    except Exception as e:
        return False, str(e)

def block_device(mac: str) -> dict:
    """Block all traffic from device MAC using iptables."""
    conn = get_conn()
    d = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
    conn.close()
    if not d:
        return {"success": False, "message": "Device not found"}
    ip = d["ip"]
    ok, err = _run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    _run(["iptables", "-I", "INPUT",   "-s", ip, "-j", "DROP"])
    if ok:
        conn = get_conn()
        conn.execute("UPDATE devices SET is_isolated=1 WHERE mac=?", (mac,))
        conn.commit()
        conn.close()
        insert_event(mac, "isolation", f"Device {ip} BLOCKED via iptables")
    return {"success": ok, "action": "block", "ip": ip, "error": err or None}

def quarantine_device(mac: str) -> dict:
    """Quarantine: allow DNS only, block everything else."""
    conn = get_conn()
    d = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
    conn.close()
    if not d:
        return {"success": False, "message": "Device not found"}
    ip = d["ip"]
    # Allow DNS (UDP 53)
    _run(["iptables", "-I", "FORWARD", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    # Block everything else
    ok, err = _run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    if ok:
        insert_event(mac, "quarantine", f"Device {ip} QUARANTINED (DNS-only)")
    return {"success": ok, "action": "quarantine", "ip": ip, "error": err or None}

def unblock_device(mac: str) -> dict:
    """Remove iptables rules for device."""
    conn = get_conn()
    d = conn.execute("SELECT ip FROM devices WHERE mac=?", (mac,)).fetchone()
    conn.close()
    if not d:
        return {"success": False, "message": "Device not found"}
    ip = d["ip"]
    _run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    _run(["iptables", "-D", "INPUT",   "-s", ip, "-j", "DROP"])
    conn = get_conn()
    conn.execute("UPDATE devices SET is_isolated=0 WHERE mac=?", (mac,))
    conn.commit()
    conn.close()
    insert_event(mac, "unblock", f"Device {ip} isolation removed")
    return {"success": True, "action": "unblock", "ip": ip}