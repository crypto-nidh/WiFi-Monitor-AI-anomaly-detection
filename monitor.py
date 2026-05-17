"""
WiFi Threat Monitor with AI Anomaly Detection
Core monitoring engine - scans network, detects threats, flags anomalies
"""

import time
import socket
import struct
import random
import hashlib
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional
import subprocess
import platform

# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class Device:
    mac: str
    ip: str
    hostname: str
    vendor: str
    first_seen: str
    last_seen: str
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    open_ports: list = field(default_factory=list)
    threat_score: float = 0.0
    flags: list = field(default_factory=list)
    is_gateway: bool = False
    is_new: bool = True
    anomaly_score: float = 0.0


@dataclass
class ThreatEvent:
    event_id: str
    timestamp: str
    threat_type: str
    severity: str          # low / medium / high / critical
    source_mac: str
    source_ip: str
    description: str
    recommendation: str
    raw_data: dict = field(default_factory=dict)


@dataclass
class NetworkStats:
    total_devices: int = 0
    new_devices: int = 0
    threats_detected: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    anomalies: int = 0
    scan_time: str = ""
    gateway_ip: str = ""
    ssid: str = "Unknown"
    security: str = "Unknown"


# ─── Vendor OUI Database (partial, for demo) ─────────────────────────────────

OUI_DB = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:11": "Google",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:17:F2": "Apple",
    "A4:C3:F0": "Apple",
    "3C:22:FB": "Apple",
    "00:1B:44": "SanDisk",
    "FC:FB:FB": "Cisco",
    "00:1E:13": "Cisco",
    "00:23:F8": "Huawei",
    "54:89:98": "Huawei",
    "00:15:5D": "Microsoft (Hyper-V)",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:26:B9": "Dell",
    "18:DB:F2": "Dell",
    "00:90:96": "Unknown/Spoofed",
    "DE:AD:BE": "Suspicious",
}


def lookup_vendor(mac: str) -> str:
    prefix = mac[:8].upper()
    for oui, vendor in OUI_DB.items():
        if prefix.startswith(oui.replace(":", "").upper()[:6]):
            return vendor
    return "Unknown"


# ─── AI Anomaly Detector ─────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Simple statistical anomaly detector using rolling z-score + rule engine.
    In a real deployment you'd use Isolation Forest or LSTM here.
    """

    def __init__(self, window=50):
        self.window = window
        self.history: dict[str, deque] = defaultdict(lambda: deque(maxlen=window))
        self.baselines: dict[str, dict] = {}

    def update(self, mac: str, feature_vec: dict) -> float:
        """Feed new observation, return anomaly score 0-1."""
        combined = (
            feature_vec.get("pps", 0) * 0.4 +
            feature_vec.get("bps", 0) / 10000 * 0.3 +
            feature_vec.get("port_scan_score", 0) * 0.3
        )
        self.history[mac].append(combined)

        if len(self.history[mac]) < 10:
            return 0.0

        vals = list(self.history[mac])
        mean = sum(vals) / len(vals)
        variance = sum((v - mean) ** 2 for v in vals) / len(vals)
        std = variance ** 0.5

        if std < 1e-9:
            return 0.0

        z = abs(combined - mean) / std
        # sigmoid-like normalisation: z=2 → 0.5, z=4 → 0.88
        score = 1 - 1 / (1 + (z / 2) ** 2)
        return min(score, 1.0)

    def learn_baseline(self, mac: str):
        if len(self.history[mac]) >= 10:
            vals = list(self.history[mac])
            self.baselines[mac] = {
                "mean": sum(vals) / len(vals),
                "std": (sum((v - sum(vals)/len(vals))**2 for v in vals) / len(vals)) ** 0.5
            }


# ─── Threat Rule Engine ───────────────────────────────────────────────────────

class ThreatRuleEngine:

    def check_arp_spoofing(self, devices: dict, arp_table: dict) -> list[ThreatEvent]:
        events = []
        seen_ips = defaultdict(list)
        for mac, dev in devices.items():
            seen_ips[dev.ip].append(mac)

        for ip, macs in seen_ips.items():
            if len(macs) > 1:
                events.append(ThreatEvent(
                    event_id=hashlib.md5(f"arp_{ip}_{time.time()}".encode()).hexdigest()[:8],
                    timestamp=datetime.now().isoformat(),
                    threat_type="ARP Spoofing",
                    severity="critical",
                    source_mac=macs[0],
                    source_ip=ip,
                    description=f"Multiple MACs ({', '.join(macs)}) claiming IP {ip}. Possible MITM attack.",
                    recommendation="Isolate device, check for rogue APs. Enable Dynamic ARP Inspection on managed switches.",
                    raw_data={"conflicting_macs": macs}
                ))
        return events

    def check_port_scan(self, device: Device, scan_threshold=15) -> Optional[ThreatEvent]:
        if len(device.open_ports) > scan_threshold:
            return ThreatEvent(
                event_id=hashlib.md5(f"portscan_{device.mac}_{time.time()}".encode()).hexdigest()[:8],
                timestamp=datetime.now().isoformat(),
                threat_type="Port Scan Detected",
                severity="high",
                source_mac=device.mac,
                source_ip=device.ip,
                description=f"Device has {len(device.open_ports)} open ports — possible reconnaissance.",
                recommendation="Review open services. Block device if unexpected.",
                raw_data={"open_ports": device.open_ports}
            )
        return None

    def check_high_traffic(self, device: Device, bps_threshold=5_000_000) -> Optional[ThreatEvent]:
        if device.bytes_sent > bps_threshold:
            return ThreatEvent(
                event_id=hashlib.md5(f"traffic_{device.mac}_{time.time()}".encode()).hexdigest()[:8],
                timestamp=datetime.now().isoformat(),
                threat_type="Abnormal Traffic Volume",
                severity="medium",
                source_mac=device.mac,
                source_ip=device.ip,
                description=f"Device sending {device.bytes_sent/1_000_000:.1f} MB — may indicate data exfiltration.",
                recommendation="Monitor outbound connections. Check for malware or data leak.",
                raw_data={"bytes_sent": device.bytes_sent}
            )
        return None

    def check_suspicious_mac(self, device: Device) -> Optional[ThreatEvent]:
        mac_parts = device.mac.split(":")
        if len(mac_parts) != 6:
            return None
        # Check locally-administered bit (bit 1 of first octet = MAC randomization/spoofing)
        first_octet = int(mac_parts[0], 16)
        if first_octet & 0x02:
            return ThreatEvent(
                event_id=hashlib.md5(f"macspoof_{device.mac}".encode()).hexdigest()[:8],
                timestamp=datetime.now().isoformat(),
                threat_type="MAC Randomization / Spoofing",
                severity="low",
                source_mac=device.mac,
                source_ip=device.ip,
                description=f"Device {device.mac} uses locally-administered MAC — could be spoofed or randomized.",
                recommendation="Verify device identity through other means (hostname, behaviour).",
                raw_data={}
            )
        return None


# ─── Network Scanner ──────────────────────────────────────────────────────────

class WiFiMonitor:

    def __init__(self):
        self.devices: dict[str, Device] = {}
        self.threat_events: list[ThreatEvent] = []
        self.stats = NetworkStats()
        self.anomaly_detector = AnomalyDetector()
        self.rule_engine = ThreatRuleEngine()
        self.arp_table: dict[str, str] = {}
        self._running = False
        self._lock = threading.Lock()
        self._known_macs: set[str] = set()

    def get_gateway(self) -> str:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=3
            )
            parts = result.stdout.strip().split()
            idx = parts.index("via") + 1 if "via" in parts else -1
            return parts[idx] if idx > 0 else "192.168.1.1"
        except Exception:
            return "192.168.1.1"

    def get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def _generate_demo_mac(self, seed: str) -> str:
        h = hashlib.md5(seed.encode()).hexdigest()
        return ":".join(h[i:i+2] for i in range(0, 12, 2))

    def _simulate_scan(self) -> list[dict]:
        """
        Simulates network scan results for demo.
        In production: use scapy ARP scan or nmap.
        """
        gateway = self.get_gateway()
        base = ".".join(gateway.split(".")[:3])

        demo_devices = [
            {"ip": gateway,          "mac": "FC:FB:FB:12:34:56", "hostname": "router.local"},
            {"ip": f"{base}.101",    "mac": "A4:C3:F0:AA:BB:CC", "hostname": "macbook-pro.local"},
            {"ip": f"{base}.102",    "mac": "B8:27:EB:DE:AD:01", "hostname": "raspberrypi.local"},
            {"ip": f"{base}.103",    "mac": "00:23:F8:AB:12:34", "hostname": "android-phone"},
            {"ip": f"{base}.104",    "mac": "DE:AD:BE:EF:CA:FE", "hostname": "unknown-device"},  # suspicious MAC
            {"ip": f"{base}.105",    "mac": "54:89:98:77:66:55", "hostname": "huawei-tablet"},
            {"ip": f"{base}.106",    "mac": "00:15:5D:11:22:33", "hostname": "windows-pc"},
        ]
        return demo_devices

    def scan_network(self):
        """Perform one full network scan cycle."""
        raw = self._simulate_scan()
        gateway = self.get_gateway()
        now = datetime.now().isoformat()
        new_count = 0

        with self._lock:
            seen_macs = set()

            for entry in raw:
                mac = entry["mac"]
                ip = entry["ip"]
                seen_macs.add(mac)

                is_new = mac not in self.devices

                if is_new:
                    new_count += 1
                    dev = Device(
                        mac=mac,
                        ip=ip,
                        hostname=entry.get("hostname", ip),
                        vendor=lookup_vendor(mac),
                        first_seen=now,
                        last_seen=now,
                        is_gateway=(ip == gateway),
                        is_new=True
                    )
                else:
                    dev = self.devices[mac]
                    dev.ip = ip
                    dev.last_seen = now
                    dev.is_new = False

                # Simulate traffic counters
                dev.packets_sent += random.randint(0, 200)
                dev.packets_recv += random.randint(0, 150)
                dev.bytes_sent += random.randint(0, 50_000)
                dev.bytes_recv += random.randint(0, 80_000)

                # Simulate open ports for demo
                if dev.is_gateway:
                    dev.open_ports = [80, 443, 22, 53, 8080]
                elif "raspberrypi" in dev.hostname:
                    dev.open_ports = [22, 8080, 5000, 80, 443, 3306, 5432, 6379, 27017, 9000,
                                      9001, 9002, 9003, 9004, 9005, 9006, 9007]  # many ports → threat
                else:
                    dev.open_ports = random.sample(range(80, 9000), random.randint(1, 4))

                # AI anomaly scoring
                feature_vec = {
                    "pps": dev.packets_sent / max(1, (time.time() % 60)),
                    "bps": dev.bytes_sent,
                    "port_scan_score": len(dev.open_ports) / 20.0
                }
                dev.anomaly_score = self.anomaly_detector.update(mac, feature_vec)

                # Rule-based threat scoring
                score = dev.anomaly_score * 40
                flags = []

                suspicious_event = self.rule_engine.check_suspicious_mac(dev)
                if suspicious_event:
                    score += 20
                    flags.append("Suspicious MAC")
                    self._add_event(suspicious_event)

                port_event = self.rule_engine.check_port_scan(dev)
                if port_event:
                    score += 35
                    flags.append("Port Scan")
                    self._add_event(port_event)

                traffic_event = self.rule_engine.check_high_traffic(dev)
                if traffic_event:
                    score += 25
                    flags.append("High Traffic")
                    self._add_event(traffic_event)

                dev.threat_score = min(score, 100)
                dev.flags = flags
                self.devices[mac] = dev

            # ARP spoofing check (simulated conflict for demo)
            if len(self.devices) > 3:
                first_two = list(self.devices.values())[:2]
                fake_conflict = {first_two[0].ip: [first_two[0].mac, first_two[1].mac]}
                for ip, macs in fake_conflict.items():
                    if len(macs) > 1 and random.random() < 0.02:  # 2% chance per scan
                        self._add_event(ThreatEvent(
                            event_id=hashlib.md5(f"arp_{ip}_{time.time()}".encode()).hexdigest()[:8],
                            timestamp=now,
                            threat_type="ARP Spoofing",
                            severity="critical",
                            source_mac=macs[1],
                            source_ip=ip,
                            description=f"ARP conflict on {ip} — two MACs responding.",
                            recommendation="Enable Dynamic ARP Inspection. Isolate suspicious device immediately.",
                            raw_data={}
                        ))

            # Update global stats
            self.stats.total_devices = len(self.devices)
            self.stats.new_devices = new_count
            self.stats.threats_detected = len([
                d for d in self.devices.values() if d.threat_score > 30
            ])
            self.stats.anomalies = len([
                d for d in self.devices.values() if d.anomaly_score > 0.5
            ])
            self.stats.packets_per_second = round(
                sum(d.packets_sent for d in self.devices.values()) / 60, 1
            )
            self.stats.bytes_per_second = round(
                sum(d.bytes_sent for d in self.devices.values()) / 60, 0
            )
            self.stats.scan_time = now
            self.stats.gateway_ip = gateway
            self.stats.ssid = "HomeNetwork-5G"
            self.stats.security = "WPA3"

    def _add_event(self, event: ThreatEvent):
        """Add threat event (deduplicated by type+MAC within 60s)."""
        cutoff = (datetime.now() - timedelta(seconds=60)).isoformat()
        duplicate = any(
            e.threat_type == event.threat_type and
            e.source_mac == event.source_mac and
            e.timestamp > cutoff
            for e in self.threat_events
        )
        if not duplicate:
            self.threat_events.insert(0, event)
            self.threat_events = self.threat_events[:100]  # cap at 100

    def get_snapshot(self) -> dict:
        with self._lock:
            return {
                "devices": [asdict(d) for d in self.devices.values()],
                "events": [asdict(e) for e in self.threat_events[:20]],
                "stats": asdict(self.stats)
            }

    def start(self, interval=10):
        self._running = True
        def loop():
            while self._running:
                try:
                    self.scan_network()
                except Exception as e:
                    print(f"Scan error: {e}")
                time.sleep(interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t

    def stop(self):
        self._running = False


# ─── Entry point for testing ──────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting WiFi Monitor (demo mode)...")
    monitor = WiFiMonitor()
    monitor.scan_network()
    snap = monitor.get_snapshot()
    print(f"\n✅ Devices found: {snap['stats']['total_devices']}")
    print(f"⚠️  Threats: {snap['stats']['threats_detected']}")
    print(f"🤖 Anomalies: {snap['stats']['anomalies']}")
    for d in snap["devices"]:
        print(f"  {d['ip']:16s}  {d['mac']}  {d['vendor']:20s}  score={d['threat_score']:.0f}")
    print("\n--- Events ---")
    for e in snap["events"]:
        print(f"  [{e['severity'].upper():8s}] {e['threat_type']} — {e['description'][:60]}")