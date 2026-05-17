"""
WiFi Threat Monitor — REAL Network Scanner
==========================================
Scans YOUR actual WiFi network using:
  - Scapy ARP sweep (discovers live devices + MACs)
  - nmap port scan (finds open services)
  - AI anomaly detection (flags unusual behaviour)
  - Rule engine (ARP spoof, port scan, MAC spoof, dangerous ports)

Run with:  sudo python monitor.py
Requires:  pip install scapy flask flask-socketio
           sudo apt install nmap   (Linux)
           brew install nmap       (Mac)
"""

import os, sys, time, socket, hashlib, threading, subprocess, platform
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Dependency check ──────────────────────────────────────────────────────────
def check_deps():
    missing = []
    try: import scapy.all
    except ImportError: missing.append("scapy")
    try: import flask
    except ImportError: missing.append("flask")
    try: import flask_socketio
    except ImportError: missing.append("flask-socketio")
    if missing:
        print(f"[ERROR] Missing: {', '.join(missing)}")
        print(f"Fix:    pip install {' '.join(missing)}")
        sys.exit(1)

check_deps()
from scapy.all import ARP, Ether, srp, conf as scapy_conf
scapy_conf.verb = 0

# ── Vendor OUI lookup ─────────────────────────────────────────────────────────
OUI_DB = {
    "00:50:56": "VMware",       "00:0C:29": "VMware",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:17:F2": "Apple",        "A4:C3:F0": "Apple",
    "3C:22:FB": "Apple",        "F4:D4:88": "Apple",
    "F8:FF:C2": "Apple",        "00:88:65": "Apple",
    "FC:FB:FB": "Cisco",        "00:1E:13": "Cisco",
    "00:23:F8": "Huawei",       "54:89:98": "Huawei",
    "00:15:5D": "Microsoft",    "00:50:F2": "Microsoft",
    "00:26:B9": "Dell",         "18:DB:F2": "Dell",
    "00:25:90": "Samsung",      "CC:07:AB": "Samsung",
    "84:2B:2B": "Samsung",
    "10:02:B5": "Xiaomi",       "28:6C:07": "Xiaomi",
    "8C:BE:BE": "TP-Link",      "EC:08:6B": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:09:5B": "Netgear",      "20:4E:7F": "Netgear",
    "00:1A:11": "Google",
    "08:00:27": "VirtualBox",   "52:54:00": "QEMU/KVM",
}

def lookup_vendor(mac: str) -> str:
    oui = mac.upper()[:8]
    for prefix, vendor in OUI_DB.items():
        if oui.startswith(prefix.upper()):
            return vendor
    return "Unknown"

# ── Data Models ───────────────────────────────────────────────────────────────
@dataclass
class Device:
    mac: str; ip: str; hostname: str; vendor: str
    first_seen: str; last_seen: str
    packets_sent: int = 0; packets_recv: int = 0
    bytes_sent: int = 0;   bytes_recv: int = 0
    open_ports: list = field(default_factory=list)
    threat_score: float = 0.0
    flags: list = field(default_factory=list)
    is_gateway: bool = False; is_new: bool = True
    anomaly_score: float = 0.0

@dataclass
class ThreatEvent:
    event_id: str; timestamp: str; threat_type: str; severity: str
    source_mac: str; source_ip: str; description: str; recommendation: str
    raw_data: dict = field(default_factory=dict)

@dataclass
class NetworkStats:
    total_devices: int = 0; new_devices: int = 0
    threats_detected: int = 0; anomalies: int = 0
    packets_per_second: float = 0.0; bytes_per_second: float = 0.0
    scan_time: str = ""; gateway_ip: str = ""
    ssid: str = "Unknown"; security: str = "Unknown"
    local_ip: str = ""; subnet: str = ""

# ── Network Utilities ─────────────────────────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return ip
    except: return "127.0.0.1"

def get_gateway() -> str:
    try:
        system = platform.system()
        if system == "Linux":
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if parts[1] == "00000000":
                        h = parts[2]
                        return ".".join(str(int(h[i:i+2], 16)) for i in [6,4,2,0])
        elif system == "Darwin":
            r = subprocess.run(["netstat","-rn"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if line.startswith("default"):
                    return line.split()[1]
        elif system == "Windows":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "Default Gateway" in line:
                    gw = line.split(":")[-1].strip()
                    if gw: return gw
    except: pass
    local = get_local_ip()
    return ".".join(local.split(".")[:3]) + ".1"

def get_wifi_info() -> dict:
    info = {"ssid": "Unknown", "security": "Unknown"}
    try:
        system = platform.system()
        if system == "Linux":
            r = subprocess.run(["iwgetid","-r"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0: info["ssid"] = r.stdout.strip() or "Unknown"
            r2 = subprocess.run(["nmcli","-t","-f","ACTIVE,SSID,SECURITY","dev","wifi"],
                                 capture_output=True, text=True, timeout=3)
            for line in r2.stdout.splitlines():
                if line.startswith("yes:"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        info["ssid"] = parts[1] or info["ssid"]
                        info["security"] = parts[2] or "Unknown"
        elif system == "Darwin":
            r = subprocess.run(["/System/Library/PrivateFrameworks/Apple80211.framework"
                                "/Versions/Current/Resources/airport","-I"],
                               capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                l = line.strip()
                if l.startswith("SSID:"): info["ssid"] = l.split(":",1)[-1].strip()
                elif l.startswith("link auth:"): info["security"] = l.split(":",1)[-1].strip()
        elif system == "Windows":
            r = subprocess.run(["netsh","wlan","show","interfaces"],
                               capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                l = line.strip()
                if "SSID" in l and "BSSID" not in l:
                    info["ssid"] = l.split(":")[-1].strip()
                elif "Authentication" in l:
                    info["security"] = l.split(":")[-1].strip()
    except: pass
    return info

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except: return ip

def is_mac_spoofed(mac: str) -> bool:
    try: return bool(int(mac.split(":")[0], 16) & 0x02)
    except: return False

# ── ARP Scanner (REAL) ────────────────────────────────────────────────────────
def arp_scan(subnet: str, timeout: int = 3) -> list[dict]:
    """Real ARP scan — finds all live hosts on your network."""
    print(f"[SCAN] ARP sweeping {subnet} ...")
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        results = [{"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in answered]
        print(f"[SCAN] {len(results)} live hosts found")
        return results
    except PermissionError:
        print("[ERROR] ARP scan needs root. Run: sudo python monitor.py")
        return []
    except Exception as e:
        print(f"[ERROR] ARP scan failed: {e}")
        return []

# ── Port Scanner ──────────────────────────────────────────────────────────────
COMMON_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,554,3389,5900,8080,8443"
DANGEROUS_PORTS = {
    4444: "Metasploit shell", 1337: "Common backdoor", 31337: "Elite/backdoor",
    12345: "NetBus trojan", 54321: "Reverse shell",
    6667: "IRC botnet C2", 23: "Telnet (unencrypted)", 21: "FTP (unencrypted)",
}

def quick_port_scan(ip: str, ports: str = COMMON_PORTS) -> list[int]:
    """nmap fast port scan, falls back to socket if nmap missing."""
    open_ports = []
    try:
        r = subprocess.run(
            ["nmap", "-T4", "--open", "-p", ports, ip, "--host-timeout", "5s"],
            capture_output=True, text=True, timeout=12
        )
        for line in r.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(int(line.split("/")[0].strip()))
    except FileNotFoundError:
        # Fallback: raw socket scan
        for p in map(int, ports.split(",")):
            try:
                s = socket.socket(); s.settimeout(0.4)
                if s.connect_ex((ip, p)) == 0: open_ports.append(p)
                s.close()
            except: pass
    except Exception as e:
        print(f"[WARN] Port scan {ip}: {e}")
    return open_ports

# ── AI Anomaly Detector ───────────────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self, window=30):
        self.window = window
        self.history: dict[str, deque] = defaultdict(lambda: deque(maxlen=window))

    def update(self, mac: str, pps: float, bps: float, port_count: int) -> float:
        score = pps * 0.4 + (bps / 100000) * 0.3 + (port_count / 20.0) * 0.3
        self.history[mac].append(score)
        if len(self.history[mac]) < 5: return 0.0
        vals = list(self.history[mac])
        mean = sum(vals) / len(vals)
        std = (sum((v-mean)**2 for v in vals) / len(vals)) ** 0.5
        if std < 1e-9: return 0.0
        z = abs(score - mean) / std
        return min(1.0, z / 5.0)

# ── Threat Rules ──────────────────────────────────────────────────────────────
class ThreatRuleEngine:

    def check_mac_spoof(self, dev: Device) -> Optional[ThreatEvent]:
        if is_mac_spoofed(dev.mac):
            return ThreatEvent(
                event_id=hashlib.md5(f"macspoof_{dev.mac}".encode()).hexdigest()[:8],
                timestamp=datetime.now().isoformat(),
                threat_type="MAC Randomization / Spoofing",  severity="medium",
                source_mac=dev.mac, source_ip=dev.ip,
                description=f"{dev.ip} uses locally-administered MAC ({dev.mac}) — may be spoofed/randomized.",
                recommendation="Verify device. Enable 802.1X for certificate-based auth.",
            )

    def check_many_ports(self, dev: Device, threshold=10) -> Optional[ThreatEvent]:
        if len(dev.open_ports) >= threshold:
            return ThreatEvent(
                event_id=hashlib.md5(f"manyports_{dev.mac}".encode()).hexdigest()[:8],
                timestamp=datetime.now().isoformat(),
                threat_type="Excessive Open Ports",  severity="high",
                source_mac=dev.mac, source_ip=dev.ip,
                description=f"{dev.hostname} ({dev.ip}) has {len(dev.open_ports)} open ports — unusual.",
                recommendation="Review services. Disable unused ports. Isolate if unexpected.",
                raw_data={"ports": dev.open_ports},
            )

    def check_dangerous_ports(self, dev: Device) -> list[ThreatEvent]:
        events = []
        for port in dev.open_ports:
            if port in DANGEROUS_PORTS:
                events.append(ThreatEvent(
                    event_id=hashlib.md5(f"dport_{dev.mac}_{port}".encode()).hexdigest()[:8],
                    timestamp=datetime.now().isoformat(),
                    threat_type="Dangerous Port Open",  severity="critical",
                    source_mac=dev.mac, source_ip=dev.ip,
                    description=f"Port {port} open on {dev.ip}: {DANGEROUS_PORTS[port]}.",
                    recommendation=f"Investigate port {port} immediately. Block at firewall if unauthorized.",
                    raw_data={"port": port},
                ))
        return events

    def check_new_unknown(self, dev: Device) -> Optional[ThreatEvent]:
        if dev.is_new and dev.vendor == "Unknown" and not dev.is_gateway:
            return ThreatEvent(
                event_id=hashlib.md5(f"newunk_{dev.mac}".encode()).hexdigest()[:8],
                timestamp=datetime.now().isoformat(),
                threat_type="Unknown New Device",  severity="medium",
                source_mac=dev.mac, source_ip=dev.ip,
                description=f"Unrecognized device joined network: {dev.ip} ({dev.mac}).",
                recommendation="Identify this device. Block at router if unrecognized.",
            )

    def check_arp_spoof(self, ip_to_macs: dict) -> list[ThreatEvent]:
        events = []
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                events.append(ThreatEvent(
                    event_id=hashlib.md5(f"arp_{ip}".encode()).hexdigest()[:8],
                    timestamp=datetime.now().isoformat(),
                    threat_type="ARP Spoofing / MITM Attack",  severity="critical",
                    source_mac=macs[0], source_ip=ip,
                    description=f"MITM detected: {len(macs)} MACs claiming IP {ip}: {', '.join(macs)}",
                    recommendation="Isolate suspicious device IMMEDIATELY. Enable Dynamic ARP Inspection.",
                    raw_data={"conflicting_macs": macs},
                ))
        return events

# ── Main Monitor ──────────────────────────────────────────────────────────────
class WiFiMonitor:

    def __init__(self):
        self.devices: dict[str, Device] = {}
        self.threat_events: list[ThreatEvent] = []
        self.stats = NetworkStats()
        self.anomaly = AnomalyDetector()
        self.rules = ThreatRuleEngine()
        self._lock = threading.Lock()
        self._scan_count = 0

        # Detect real network info
        self.local_ip = get_local_ip()
        self.gateway  = get_gateway()
        self.subnet   = ".".join(self.local_ip.split(".")[:3]) + ".0/24"
        self.wifi_info = get_wifi_info()

        print(f"[INFO] Local IP : {self.local_ip}")
        print(f"[INFO] Gateway  : {self.gateway}")
        print(f"[INFO] Subnet   : {self.subnet}")
        print(f"[INFO] WiFi     : {self.wifi_info['ssid']} ({self.wifi_info['security']})")

    def scan_network(self):
        self._scan_count += 1
        now = datetime.now().isoformat()
        new_count = 0

        # ── 1. Real ARP scan ──────────────────────────────────────────────────
        raw_hosts = arp_scan(self.subnet)
        if not raw_hosts:
            self.stats.scan_time = now
            return

        with self._lock:
            # ── 2. Process hosts ──────────────────────────────────────────────
            for host in raw_hosts:
                ip, mac = host["ip"], host["mac"]
                is_new = mac not in self.devices

                if is_new:
                    new_count += 1
                    dev = Device(
                        mac=mac, ip=ip,
                        hostname=resolve_hostname(ip),
                        vendor=lookup_vendor(mac),
                        first_seen=now, last_seen=now,
                        is_gateway=(ip == self.gateway),
                        is_new=True,
                    )
                    dev.open_ports = quick_port_scan(ip)
                else:
                    dev = self.devices[mac]
                    dev.ip = ip
                    dev.last_seen = now
                    dev.is_new = False
                    if self._scan_count % 5 == 0:
                        dev.open_ports = quick_port_scan(ip)

                # ── 3. AI anomaly ─────────────────────────────────────────────
                dev.anomaly_score = self.anomaly.update(
                    mac,
                    dev.packets_sent / max(1, self._scan_count),
                    dev.bytes_sent   / max(1, self._scan_count),
                    len(dev.open_ports),
                )

                # ── 4. Rule engine ────────────────────────────────────────────
                score, flags = 0.0, []
                if dev.is_gateway: flags.append("gateway")

                for evt, inc, flag in [
                    (self.rules.check_mac_spoof(dev),     20, "MAC Spoofed"),
                    (self.rules.check_many_ports(dev),    30, "Too Many Ports"),
                    (self.rules.check_new_unknown(dev),   15, "Unknown Device"),
                ]:
                    if evt:
                        score += inc; flags.append(flag)
                        self._add_event(evt)

                for dp_evt in self.rules.check_dangerous_ports(dev):
                    score += 40
                    flags.append(f"Port {dp_evt.raw_data.get('port','?')}")
                    self._add_event(dp_evt)

                score += dev.anomaly_score * 30
                dev.threat_score = min(round(score), 100)
                dev.flags = list(set(flags))
                self.devices[mac] = dev

            # ── 5. ARP spoof check ────────────────────────────────────────────
            ip_map = defaultdict(list)
            for m, d in self.devices.items(): ip_map[d.ip].append(m)
            for evt in self.rules.check_arp_spoof(ip_map):
                self._add_event(evt)

            # ── 6. Stats ──────────────────────────────────────────────────────
            self.stats.total_devices    = len(self.devices)
            self.stats.new_devices      = new_count
            self.stats.threats_detected = sum(1 for d in self.devices.values() if d.threat_score > 30)
            self.stats.anomalies        = sum(1 for d in self.devices.values() if d.anomaly_score > 0.5)
            self.stats.scan_time        = now
            self.stats.gateway_ip       = self.gateway
            self.stats.local_ip         = self.local_ip
            self.stats.subnet           = self.subnet
            self.stats.ssid             = self.wifi_info["ssid"]
            self.stats.security         = self.wifi_info["security"]

        print(f"[DONE] #{self._scan_count}: {self.stats.total_devices} devices, "
              f"{self.stats.threats_detected} threats")

    def _add_event(self, event: ThreatEvent):
        cutoff = (datetime.now() - timedelta(minutes=2)).isoformat()
        dup = any(e.threat_type == event.threat_type and
                  e.source_mac == event.source_mac and
                  e.timestamp > cutoff
                  for e in self.threat_events)
        if not dup:
            self.threat_events.insert(0, event)
            self.threat_events = self.threat_events[:200]

    def get_snapshot(self) -> dict:
        with self._lock:
            return {
                "devices": [asdict(d) for d in self.devices.values()],
                "events":  [asdict(e) for e in self.threat_events[:30]],
                "stats":   asdict(self.stats),
            }

    def start_background(self, interval=30):
        def loop():
            while True:
                try: self.scan_network()
                except Exception as e: print(f"[ERROR] {e}")
                time.sleep(interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t


# ── CLI mode ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.name != "nt" and os.geteuid() != 0:
        print("[ERROR] Run as root: sudo python monitor.py")
        sys.exit(1)
    mon = WiFiMonitor()
    mon.scan_network()
    snap = mon.get_snapshot()
    print(f"\nDevices: {snap['stats']['total_devices']} | Threats: {snap['stats']['threats_detected']}")
    for d in sorted(snap["devices"], key=lambda x: x["threat_score"], reverse=True):
        icon = "🚨" if d["threat_score"] > 60 else "⚠️ " if d["threat_score"] > 30 else "✅"
        print(f"  {icon} {d['ip']:16s}  {d['mac']}  {d['vendor']:18s}  score={d['threat_score']}")