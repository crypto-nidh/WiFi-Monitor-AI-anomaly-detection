from flask import Blueprint, jsonify, request, send_file
from models.database import get_conn, get_device_timeline
from engines.cve_engine import analyze_device_cves
from engines.scoring_engine import compute_network_score
from engines.threat_intel import check_ip
from actions.isolator import block_device, quarantine_device
from actions.reporter import generate_report
from api.copilot import copilot_query

api = Blueprint("api", __name__, url_prefix="/api/v3")

@api.route("/devices")
def devices():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@api.route("/alerts")
def alerts():
    limit = request.args.get("limit", 50, type=int)
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@api.route("/device/<mac>/cves")
def device_cves(mac):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM cve_findings WHERE device_mac=? ORDER BY cvss_score DESC", (mac,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@api.route("/device/<mac>/timeline")
def device_timeline(mac):
    return jsonify(get_device_timeline(mac))

@api.route("/device/<mac>/isolate", methods=["POST"])
def isolate(mac):
    action = request.json.get("action", "block")  # block | quarantine
    result = block_device(mac) if action == "block" else quarantine_device(mac)
    return jsonify(result)

@api.route("/score")
def score():
    return jsonify(compute_network_score())

@api.route("/threat-intel/<ip>")
def threat_intel(ip):
    return jsonify(check_ip(ip))

@api.route("/report", methods=["POST"])
def report():
    fmt = request.json.get("format", "pdf")
    path = generate_report(fmt)
    return send_file(path, as_attachment=True)

@api.route("/copilot", methods=["POST"])
def copilot():
    question = request.json.get("question", "")
    return jsonify({"answer": copilot_query(question)})

@api.route("/simulate", methods=["POST"])
def simulate():
    from attack_lab import run_simulation
    sim_type = request.json.get("type")
    return jsonify(run_simulation(sim_type))

@api.route("/analytics/trends")
def trends():
    from models.database import get_security_score_history
    days = request.args.get("days", 7, type=int)
    return jsonify(get_security_score_history(days))