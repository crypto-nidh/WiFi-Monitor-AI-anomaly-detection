"""
WiFi Threat Monitor — Flask REST API
Serves real-time data to the dashboard frontend.
"""

from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO
import threading
import time
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from monitor import WiFiMonitor

app = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = "wifimonitor_secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

monitor = WiFiMonitor()

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/api/snapshot")
def snapshot():
    return jsonify(monitor.get_snapshot())


@app.route("/api/devices")
def devices():
    snap = monitor.get_snapshot()
    return jsonify(snap["devices"])


@app.route("/api/events")
def events():
    snap = monitor.get_snapshot()
    return jsonify(snap["events"])


@app.route("/api/stats")
def stats():
    snap = monitor.get_snapshot()
    return jsonify(snap["stats"])


@app.route("/api/device/<mac>")
def device_detail(mac):
    snap = monitor.get_snapshot()
    for dev in snap["devices"]:
        if dev["mac"].replace(":", "").lower() == mac.replace(":", "").lower():
            return jsonify(dev)
    return jsonify({"error": "Device not found"}), 404


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    monitor.scan_network()
    return jsonify({"status": "ok", "message": "Scan triggered"})


@socketio.on("connect")
def on_connect():
    print(f"Client connected")
    socketio.emit("snapshot", monitor.get_snapshot())


def push_updates():
    while True:
        time.sleep(8)
        monitor.scan_network()
        socketio.emit("snapshot", monitor.get_snapshot())


if __name__ == "__main__":
    print("WiFi Threat Monitor starting...")
    monitor.scan_network()

    update_thread = threading.Thread(target=push_updates, daemon=True)
    update_thread.start()

    print("Dashboard: http://localhost:5050")
    socketio.run(app, host="0.0.0.0", port=5050, debug=False, allow_unsafe_werkzeug=True)