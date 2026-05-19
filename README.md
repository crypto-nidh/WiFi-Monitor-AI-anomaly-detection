# 🛡️ WiFi Threat Monitor — Setup Guide

## Files in this folder
```
monitor.py                  ← Core scanner (ARP + ports + AI + rules)
server.py                   ← Flask web server (REST + WebSocket)
wifi_monitor_dashboard.html ← Dashboard UI
requirements.txt            ← Python dependencies
```

---

## Step 1 — Install dependencies

### Linux (Ubuntu/Kali/Parrot)
```bash
sudo apt update
sudo apt install nmap python3-pip -y
pip install -r requirements.txt
```

### macOS
```bash
brew install nmap
pip install -r requirements.txt
```

### Windows
1. Download nmap from https://nmap.org/download.html
2. Install with default options (adds nmap to PATH)
3. Run PowerShell as Administrator:
```powershell
pip install -r requirements.txt
```

---

## Step 2 — Run the monitor

### Linux / macOS (needs sudo for raw packets)
```bash
sudo python server.py
```

### Windows (run as Administrator)
```powershell
python server.py
```

---

## Step 3 — Open dashboard
```
http://localhost:5050
```

---

## What it detects

| Threat | How |
|--------|-----|
| ARP Spoofing / MITM | Multiple MACs claiming same IP |
| Port Scan Activity | Device with many open ports |
| Dangerous Ports | Metasploit (4444), backdoors (1337, 31337), Telnet (23) |
| MAC Spoofing | Locally-administered MAC bit |
| Unknown New Device | Unrecognized vendor joining network |
| AI Anomaly | Statistical deviation from device baseline |

---

## API Endpoints (if you want to integrate)
```
GET  /api/snapshot   → full data (devices + events + stats)
GET  /api/devices    → device list
GET  /api/events     → threat events
GET  /api/stats      → network stats
POST /api/scan       → trigger immediate scan
```

---

## Troubleshooting

**"Permission denied" / "No hosts found"**
→ Run with sudo (Linux/Mac) or as Administrator (Windows)

**"scapy not found"**
→ pip install scapy

**"nmap not found"**
→ Install nmap (see Step 1). The tool falls back to socket scan if nmap is missing.

**Dashboard shows no data**
→ Make sure server.py is running AND you're on WiFi (not VPN)