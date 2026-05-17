# 🛡️ WiFi Threat Monitor with AI Anomaly Detection

A Python-based network security tool that monitors your WiFi for threats in real-time.

## Features
- 📡 **Network Scanner** — Auto-discovers all devices on your network
- 🤖 **AI Anomaly Detection** — Statistical z-score engine flags unusual behavior
- 🚨 **Threat Rule Engine** — Detects ARP spoofing, port scans, MAC spoofing, high traffic
- 📊 **Live Dashboard** — Beautiful dark-themed web UI with real-time updates
- 🔔 **Instant Alerts** — Toast notifications for critical threats

## Setup

```bash
# 1. Install dependencies (Linux/Mac)
pip install -r requirements.txt

# 2. Run the backend monitor (needs sudo for raw packet capture)
sudo python server.py

# 3. Open dashboard
http://localhost:5050
```

## Architecture

```
monitor.py       — Core engine: scanning, AI detection, rule engine
server.py        — Flask REST API + WebSocket for live updates
dashboard.html   — Frontend: real-time threat dashboard
```

## Threat Detection Methods

| Method | What it catches |
|--------|----------------|
| ARP Spoofing | Multiple MACs claiming same IP (MITM attacks) |
| Port Scan | Devices with abnormally many open ports |
| MAC Spoofing | Locally-administered MAC addresses |
| High Traffic | Unusual data volumes (exfiltration) |
| AI Anomaly | Statistical deviation from device baseline |

## For Production Use
- Replace `_simulate_scan()` with `scapy` ARP sweep
- Add Telegram/email alerts
- Store events in SQLite database
- Add PCAP analysis for deep packet inspection
