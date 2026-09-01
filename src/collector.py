import os
import csv
import pandas as pd
from flask import Flask, request, jsonify
from prometheus_client import start_http_server, Counter, Gauge

from models.hybrid_engine import HybridEngine
from core.remediation import trigger_remediation
from config.settings import REAL_DATA_PATH
from core.alerting import send_gmail_alert
from core.jira_ticketing import create_jira_ticket
from core.features import extract_file_and_connection
from core.time_features import parse_duration_ms

app = Flask(__name__)

print("[+] Chargement du modèle d'IA hybride...")
engine = HybridEngine()
try:
    engine.load()
    df_history = pd.read_csv(REAL_DATA_PATH) if os.path.exists(REAL_DATA_PATH) else None
    print("[+] Modèles d'IA chargés avec succès.")
except Exception as e:
    print(f"[!] Attention, impossible de charger l'IA: {e}")
    df_history = None

FALCO_EVENTS_TOTAL = Counter("devsecops_falco_events_total", "Total des évènements Falco reçus")
AI_ANOMALY_SCORE = Gauge("devsecops_ai_anomaly_score", "Score", ["user", "pod", "rule"])
AI_ALERTS_TOTAL = Counter("devsecops_ai_alerts_total", "Total alertes", ["severity"])
REMEDIATION_TOTAL = Counter("devsecops_remediations_total", "Remediations (quarantine)", ["status"])
JIRA_TICKETS_TOTAL = Counter("devsecops_jira_tickets_total", "Tickets Jira", ["status"])

HEADERS = [
    "timestamp", "uuid", "priority", "rule", "event_scope", "node", "namespace",
    "pod", "container_id", "container_name", "image", "image_tag", "user",
    "user_uid", "proc_name", "proc_exepath", "parent_process", "command",
    "event_type", "file", "connection", "command_duration_ms",
]

if not os.path.exists(REAL_DATA_PATH):
    with open(REAL_DATA_PATH, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(HEADERS)


@app.route("/events", methods=["POST"])
def receive_falco_event():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error"}), 400

    FALCO_EVENTS_TOTAL.inc()
    output_fields = data.get("output_fields", {})
    duration_ms = parse_duration_ms(
        output_fields.get("proc.duration"),
        output_fields.get("evt.duration"),
    )

    event_for_ai = {
        "timestamp": data.get("time", ""),
        "rule": data.get("rule", "Unknown"),
        "user": output_fields.get("user.name", "unknown"),
        "user_uid": output_fields.get("user.uid", "0"),
        "command": output_fields.get("proc.cmdline", ""),
        "proc_name": output_fields.get("proc.name", ""),
        "parent_process": output_fields.get("proc.pname", ""),
        "file": output_fields.get("fd.name", ""),
        "pod": output_fields.get("k8s.pod.name", "unknown"),
        "event_scope": "pod" if output_fields.get("k8s.pod.name") else "node",
        "command_duration_ms": duration_ms,
        "evt.duration": output_fields.get("evt.duration"),
        "proc.duration": output_fields.get("proc.duration"),
    }

    prediction = engine.predict(event_for_ai, history_df=df_history)
    score = prediction.get("combined_score", 0)

    AI_ANOMALY_SCORE.labels(
        user=str(event_for_ai["user"]),
        pod=str(event_for_ai["pod"]),
        rule=str(event_for_ai["rule"]),
    ).set(score)

    if score >= 70:
        AI_ALERTS_TOTAL.labels(severity="critical").inc()
    elif score >= 45:
        AI_ALERTS_TOTAL.labels(severity="moderate").inc()
    elif score >= 20:
        AI_ALERTS_TOTAL.labels(severity="suspect").inc()

    if score >= 70:
        remed_success, remed_msg, _details = trigger_remediation(data, prediction)
        REMEDIATION_TOTAL.labels(status="success" if remed_success else "failed").inc()
        ticket = create_jira_ticket(event_for_ai, prediction, remed_msg)
        if ticket:
            JIRA_TICKETS_TOTAL.labels(status="reused" if ticket.get("reused") else "created").inc()
        else:
            JIRA_TICKETS_TOTAL.labels(status="skipped").inc()
        send_gmail_alert(event_for_ai, score, remed_success, remed_msg, ticket)

    file_name, connection = extract_file_and_connection(output_fields, event_for_ai["rule"])
    row = [
        data.get("time", ""), data.get("uuid", ""), data.get("priority", "Unknown"),
        data.get("rule", "Unknown"), event_for_ai["event_scope"], data.get("hostname", "unknown"),
        output_fields.get("k8s.ns.name", ""), output_fields.get("k8s.pod.name", ""),
        output_fields.get("container.id", ""), output_fields.get("container.name", ""),
        output_fields.get("container.image.repository", ""), output_fields.get("container.image.tag", ""),
        output_fields.get("user.name", "unknown"), output_fields.get("user.uid", ""),
        output_fields.get("proc.name", "unknown"), output_fields.get("proc.exepath", ""),
        output_fields.get("proc.pname", ""), output_fields.get("proc.cmdline", ""),
        output_fields.get("evt.type", ""), file_name or output_fields.get("fd.name", ""),
        connection, duration_ms,
    ]
    with open(REAL_DATA_PATH, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)

    print(f"\n[+] Event | {event_for_ai['rule']} | dur={duration_ms:.1f}ms")
    print(f"    IA {prediction['status']} score={score:.1f} tz={event_for_ai['timestamp']}")
    return jsonify({"status": "success", "score": score}), 200


if __name__ == "__main__":
    start_http_server(8000)
    app.run(host="0.0.0.0", port=5002)
