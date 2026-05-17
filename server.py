"""
WiFi Threat Monitor — Flask Server
Run: sudo python server.py
Then open: http://localhost:5050
"""
import os, sys, time, threading
from flask import Flask, jsonify, send_file
from flask_socketio import SocketIO

sys.path.insert(0, os.path.dirname(__file__))
from monitor import WiFiMonitor

app = Flask(__name__)
app.config["SECRET_KEY"] = "wifithreatmonitor2024"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

monitor = WiFiMonitor()

# ── REST API ──────────────────────────────────────────────────────────────────
@app.route("/api/snapshot")
def snapshot():
    return jsonify(monitor.get_snapshot())

@app.route("/api/devices")
def devices():
    return jsonify(monitor.get_snapshot()["devices"])

@app.route("/api/events")
def events():
    return jsonify(monitor.get_snapshot()["events"])

@app.route("/api/stats")
def stats():
    return jsonify(monitor.get_snapshot()["stats"])

@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    threading.Thread(target=monitor.scan_network, daemon=True).start()
    return jsonify({"status": "ok", "message": "Scan started"})

@app.route("/")
def dashboard():
    # Serve the dashboard HTML file
    html_path = os.path.join(os.path.dirname(__file__), "wifi_monitor_dashboard.html")
    if os.path.exists(html_path):
        return send_file(html_path)
    return "<h1>Dashboard not found — place wifi_monitor_dashboard.html in same folder</h1>"

# ── WebSocket ─────────────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    socketio.emit("snapshot", monitor.get_snapshot())

def push_loop():
    """Push live updates every 30 seconds."""
    while True:
        time.sleep(30)
        monitor.scan_network()
        socketio.emit("snapshot", monitor.get_snapshot())

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.name != "nt" and os.geteuid() != 0:
        print("[ERROR] Run as root: sudo python server.py")
        sys.exit(1)

    print("=" * 55)
    print("  WiFi Threat Monitor — Starting up")
    print("=" * 55)

    # Initial scan
    print("[*] Running first scan...")
    monitor.scan_network()

    # Background scan thread
    pusher = threading.Thread(target=push_loop, daemon=True)
    pusher.start()

    print(f"\n[✓] Dashboard: http://localhost:5050")
    print(f"[✓] API:       http://localhost:5050/api/snapshot")
    print(f"[*] Scanning every 30 seconds...\n")

    socketio.run(app, host="0.0.0.0", port=5050, debug=False)