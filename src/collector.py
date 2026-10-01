import os
import re
import csv
import shlex
import subprocess
import json
import functools

from flask import Flask, request, jsonify
from prometheus_client import start_http_server, Counter, Gauge
import pandas as pd

from models.engine import HybridEngine
from core.remediation import trigger_remediation
from config.settings import (
    REAL_DATA_PATH,
    FALCO_CSV_COLUMNS,
    FALCO_WEBHOOK_TOKEN,
    COLLECTOR_BIND_HOST,
    COLLECTOR_WEBHOOK_PORT,
    COLLECTOR_METRICS_PORT,
    HISTORY_MAX_ROWS,
)

from core.alerting import send_gmail_alert
from core.jira_ticketing import create_jira_ticket
from core.features import extract_file_and_connection
from core.time_features import parse_duration_ms
from core.csv_io import load_falco_csv
from core.incidents import (
    create_incident,
    load_incident,
    update_status,
    trigger_jenkins,
)


# ============================================================
# CONTAINER → POD LOOKUP (fallback when k8smeta is missing)
# ============================================================

@functools.lru_cache(maxsize=512)
def _lookup_pod_by_container_id(container_id):
    """Query the Kubernetes API to find the pod owning a given container ID.
    Returns (pod_name, namespace) or (None, None) on failure.
    Result is cached per container_id for the lifetime of the process."""
    if not container_id or len(container_id) < 6:
        return None, None
    try:
        result = subprocess.run(
            [
                "kubectl", "get", "pods", "--all-namespaces",
                "-o", "json",
            ],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None, None
        pods = json.loads(result.stdout)
        for pod in pods.get("items", []):
            for cs in pod.get("status", {}).get("containerStatuses", []):
                cid = cs.get("containerID", "")
                # containerID is like "containerd://abc123..."
                if container_id in cid:
                    return (
                        pod["metadata"]["name"],
                        pod["metadata"]["namespace"],
                    )
    except Exception:
        pass
    return None, None


# ============================================================
# USER ATTRIBUTION — resolve `su` target user
# ============================================================

# su options that consume the following token as their value
_SU_ARGS_WITH_VALUE = {
    "-s", "--shell", "-c", "--command", "-g", "--group",
    "-G", "--supp-group", "-w", "--whitelist-environment",
}

# Personas created in the pod (useradd -u ...)
_KNOWN_UIDS = {
    "root": "0",
    "dev": "1001",
    "bot": "999",
    "admin": "1000",
    "attacker": "2000",
}


def resolve_su_user(cmdline, fallback_user, fallback_uid):
    """
    Falco reports user.name=root for `su -s /bin/sh dev -c ...` because root
    owns the su process. Extract the TARGET user from proc.cmdline.
    Returns (user, uid); falls back to the given values if su is not
    detected or no target user is present (plain `su` = root).
    """
    cmdline = str(cmdline or "")
    try:
        tokens = shlex.split(cmdline)
    except ValueError:
        tokens = cmdline.split()

    # `su` must be the executable itself (first token), not just a word
    # somewhere in the command line (e.g. `grep su file`).
    idx = 0 if tokens and os.path.basename(tokens[0]) == "su" else None
    if idx is None:
        return fallback_user, fallback_uid

    args, i, target = tokens[idx + 1:], 0, None
    while i < len(args):
        a = args[i]
        if a in _SU_ARGS_WITH_VALUE:      # option + value
            i += 2
        elif a.startswith("-"):            # flag: -, -l, -m, --login
            i += 1
        else:
            target = a
            break

    if not target or not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", target.lower()):
        return fallback_user, fallback_uid

    uid = _KNOWN_UIDS.get(target.lower())
    if uid is None:
        from core.iocs_loader import resolve_uid_from_role
        r = resolve_uid_from_role(target.lower())
        uid = r if r != "0" else fallback_uid
    return target, uid


_UID_TO_NAME = {v: k for k, v in _KNOWN_UIDS.items()}
_SETPRIV_UID_RE = re.compile(r"--(?:reuid|euid|ruid)[= ](\d+)")
_UNRESOLVED_USERS = {"", "<NA>", "NA", "None", "none", "unknown"}


def resolve_setpriv_user(cmdline, fallback_user, fallback_uid):
    """`setpriv --reuid=1000 ...` runs as root until it drops privileges:
    take the target UID from the command line."""
    cmdline = str(cmdline or "")
    if "setpriv" not in cmdline:
        return fallback_user, fallback_uid
    m = _SETPRIV_UID_RE.search(cmdline)
    if not m:
        return fallback_user, fallback_uid
    uid = m.group(1)
    return _UID_TO_NAME.get(uid, f"uid{uid}"), uid


def normalize_user(user, uid, uid_known=True):
    """Replace <NA>/unknown user names using the UID when Falco really sent it.
    If Falco did not send user.uid, the user stays 'unknown' (never guessed as root)."""
    uid = str(uid if uid is not None else "").replace(".0", "")
    if uid in ("nan", "NaN", "<NA>", "None", ""):
        uid_known, uid = False, "0"
    if str(user) in _UNRESOLVED_USERS:
        if uid_known:
            user = _UID_TO_NAME.get(uid, "root" if uid == "0" else f"uid{uid}")
        else:
            user = "unknown"
    return user, uid


# Only pods in these namespaces are scored/quarantined (never jenkins, falco, kube-system...)
MONITORED_NAMESPACES = {"demo-app"}

# PAM helpers spawned by su/login: authentication plumbing, not a user action
AUTH_HELPERS = {"unix_chkpwd"}

# Container startup noise: nginx entrypoint scripts (10-listen-on-ip, docker-entrypoint.sh...)
# (process names are truncated to 15 chars by the kernel: "docker-entrypoi")
ENTRYPOINT_PARENT_RE = re.compile(r"^(\d{2}-.+|docker-entrypoi.*)$")

app = Flask(__name__)


# ============================================================
# IA MODEL INITIALIZATION
# ============================================================

print("[+] Chargement du modèle d'IA hybride...")

engine = HybridEngine()
df_history = None

try:
    engine.load()

    if os.path.exists(REAL_DATA_PATH):
        df_history = load_falco_csv(REAL_DATA_PATH)

    print("[+] Modèles d'IA chargés avec succès.")

except Exception as e:
    print(f"[!] Attention, impossible de charger l'IA : {e}")
    df_history = None


# ============================================================
# PROMETHEUS METRICS
# ============================================================

FALCO_EVENTS_TOTAL = Counter(
    "devsecops_falco_events_total",
    "Total des évènements Falco reçus",
)

AI_ANOMALY_SCORE = Gauge(
    "devsecops_ai_anomaly_score",
    "Score d'anomalie IA",
    ["user", "pod", "rule"],
)

AI_ALERTS_TOTAL = Counter(
    "devsecops_ai_alerts_total",
    "Total des alertes IA",
    ["severity"],
)

REMEDIATION_TOTAL = Counter(
    "devsecops_remediations_total",
    "Remédiations de pods",
    ["status"],
)

JIRA_TICKETS_TOTAL = Counter(
    "devsecops_jira_tickets_total",
    "Tickets Jira",
    ["status"],
)

INCIDENTS_TOTAL = Counter(
    "devsecops_incidents_total",
    "Incidents créés",
    ["status"],
)


# ============================================================
# CSV CONFIGURATION
# ============================================================

HEADERS = list(FALCO_CSV_COLUMNS)


def ensure_csv_exists():
    """Creates the Falco CSV file with its header if it does not exist."""
    directory = os.path.dirname(REAL_DATA_PATH)

    if directory:
        os.makedirs(directory, exist_ok=True)

    if not os.path.exists(REAL_DATA_PATH):
        with open(REAL_DATA_PATH, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(HEADERS)

        print(f"[+] Fichier CSV créé : {REAL_DATA_PATH}")


ensure_csv_exists()


# ============================================================
# WEBHOOK AUTHENTICATION
# ============================================================

def _webhook_authorized():
    """
    Validates the Bearer token sent by Falco/Falcosidekick.
    Disabled when FALCO_WEBHOOK_TOKEN is empty (lab only).
    """
    if not FALCO_WEBHOOK_TOKEN:
        return True

    authorization = request.headers.get("Authorization", "")
    return authorization == f"Bearer {FALCO_WEBHOOK_TOKEN}"


# ============================================================
# LIVE HISTORY
# ============================================================

def _append_live_history(row):
    """Rolling in-memory history used for burst features (event_count_5min)."""
    global df_history

    record = {
        HEADERS[i]: row[i]
        for i in range(min(len(HEADERS), len(row)))
    }

    new_df = pd.DataFrame([record])

    if df_history is None or getattr(df_history, "empty", True):
        df_history = new_df
    else:
        df_history = pd.concat([df_history, new_df], ignore_index=True)

    if len(df_history) > HISTORY_MAX_ROWS:
        df_history = df_history.iloc[-HISTORY_MAX_ROWS:].reset_index(drop=True)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/healthz", methods=["GET"])
def healthz():
    model_ok = getattr(getattr(engine, "layer1", None), "model", None) is not None

    return jsonify(
        {
            "status": "ok" if model_ok else "degraded",
            "model_loaded": model_ok,
        }
    ), 200


# ============================================================
# INCIDENT ROUTES
# ============================================================

@app.route("/incidents/<iid>", methods=["GET"])
def get_incident(iid):
    if not _webhook_authorized():
        return jsonify({"status": "unauthorized"}), 401

    try:
        return jsonify(load_incident(iid)), 200
    except (ValueError, FileNotFoundError):
        return jsonify({"status": "not_found"}), 404


@app.route("/incidents/<iid>/status", methods=["POST"])
def set_incident_status(iid):
    if not _webhook_authorized():
        return jsonify({"status": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}

    try:
        status = body.get("status", "UNKNOWN")
        decision = body.get("decision")

        update_status(iid, status, decision)
        INCIDENTS_TOTAL.labels(status=status.lower()).inc()

        return "", 204
    except (ValueError, FileNotFoundError):
        return jsonify({"status": "not_found"}), 404


# ============================================================
# FALCO WEBHOOK
# ============================================================

@app.route("/events", methods=["POST"])
def receive_falco_event():

    # 1. Authenticate request
    if not _webhook_authorized():
        print("[!] Requête Falco refusée : token invalide.")
        return jsonify({"status": "unauthorized"}), 401

    # 2. Read JSON payload
    data = request.get_json(silent=True)

    if not data:
        return jsonify(
            {"status": "error", "message": "Invalid or empty JSON payload"}
        ), 400

    FALCO_EVENTS_TOTAL.inc()

    # 3. Extract Falco output fields
    output_fields = data.get("output_fields", {})

    # 4. Parse process/event duration
    duration_ms = parse_duration_ms(
        output_fields.get("proc.duration"),
        output_fields.get("evt.duration"),
    )

    # 5. Build normalized event for AI
    pod_name = output_fields.get("k8s.pod.name")
    ns_name = output_fields.get("k8s.ns.name")
    container_id = output_fields.get("container.id", "")

    # Fallback: if k8smeta didn't enrich but we have a container.id,
    # look up the pod via the Kubernetes API (cached per container_id).
    if not pod_name and container_id:
        looked_pod, looked_ns = _lookup_pod_by_container_id(container_id)
        if looked_pod:
            pod_name = looked_pod
            ns_name = looked_ns
            print(
                f"[i] k8s fallback via container.id={container_id[:12]}"
                f" -> pod={pod_name} ns={ns_name}"
            )

    has_pod = bool(pod_name)
    event_for_ai = {
        "timestamp": data.get("time", ""),
        "rule": data.get("rule", "Unknown"),
        "user": output_fields.get("user.name", "unknown"),
        "user_uid": output_fields.get("user.uid", "0"),
        "command": output_fields.get("proc.cmdline", ""),
        "proc_name": output_fields.get("proc.name", ""),
        "parent_process": output_fields.get("proc.pname", ""),
        "file": output_fields.get("fd.name", ""),
        "pod": pod_name or "unknown",
        "event_scope": "pod" if has_pod else "node",
        "command_duration_ms": duration_ms,
        "evt.duration": output_fields.get("evt.duration"),
        "proc.duration": output_fields.get("proc.duration"),
    }

    # 5b. Resolve the real user — priority order:
    #     1) user.loginuid / user.loginname (Linux audit UID, survives su/sudo)
    #     2) su/setpriv command-line parsing
    #     3) user.uid -> name mapping
    #     4) Fallback to user.name from Falco

    loginuid_raw = output_fields.get("user.loginuid")
    loginname_raw = output_fields.get("user.loginname")

    # loginuid = 4294967295 means "unset" (nobody logged in via PAM)
    loginuid_valid = (
        loginuid_raw is not None
        and str(loginuid_raw) not in ("", "<NA>", "4294967295", "-1")
    )

    if loginuid_valid:
        # Use loginuid/loginname — this is the REAL user who did `kubectl exec`
        login_uid = str(int(float(str(loginuid_raw))))
        login_name = str(loginname_raw or "")
        if login_name in _UNRESOLVED_USERS:
            login_name = _UID_TO_NAME.get(login_uid, f"uid{login_uid}")
        resolved_user, resolved_uid = login_name, login_uid
    else:
        # Fallback: parse su/setpriv from proc.cmdline
        resolved_user, resolved_uid = resolve_su_user(
            event_for_ai["command"],
            event_for_ai["user"],
            event_for_ai["user_uid"],
        )

        # setpriv (used by the test helper / real attackers dropping privileges)
        if (resolved_user, str(resolved_uid)) == (
            event_for_ai["user"], str(event_for_ai["user_uid"])
        ):
            resolved_user, resolved_uid = resolve_setpriv_user(
                event_for_ai["command"], resolved_user, resolved_uid
            )

    # <NA> / unknown user names -> resolved from the UID
    via_resolved = (resolved_user, str(resolved_uid)) != (
        event_for_ai["user"], str(event_for_ai["user_uid"])
    )
    uid_present = "user.uid" in output_fields
    resolved_user, resolved_uid = normalize_user(
        resolved_user, resolved_uid, uid_known=uid_present or via_resolved or loginuid_valid
    )

    # Record HOW the identity was resolved (audit trail)
    original_user = event_for_ai["user"]
    via = None
    if resolved_user != original_user:
        if loginuid_valid:
            via = "loginuid"
        else:
            first = os.path.basename((str(event_for_ai["command"]).split() or [""])[0])
            via = first if first in ("su", "setpriv") else "uid-lookup"

    event_for_ai["user"] = resolved_user
    event_for_ai["user_uid"] = str(resolved_uid)
    event_for_ai["via"] = via
    event_for_ai["original_user"] = original_user

    if via in ("su", "setpriv", "loginuid"):
        print(f"[i] Identité changée via {via} : {original_user} -> {resolved_user} (UID {resolved_uid})")

    # 6. Ignore events that are not related to a Kubernetes pod
    if event_for_ai["event_scope"] == "node":
        print(
            f"[i] Event hors-cluster ignoré (host, pas de pod) | "
            f"{event_for_ai['rule']}"
        )
        return jsonify({"status": "ignored", "reason": "node-scope event"}), 200

    # 6b. Ignore pods outside the monitored namespaces (e.g. jenkins, falco)
    # Use the resolved ns_name (which may come from the container-to-pod fallback)
    effective_ns = ns_name or output_fields.get("k8s.ns.name", "")
    if effective_ns not in MONITORED_NAMESPACES:
        print(
            f"[i] Namespace hors périmètre ignoré ({effective_ns or 'n/a'}) | "
            f"{event_for_ai['rule']}"
        )
        return jsonify(
            {"status": "ignored", "reason": "namespace out of scope"}
        ), 200

    # 6c. Ignore PAM helpers spawned by su (unix_chkpwd): not the user's action
    if event_for_ai["proc_name"] in AUTH_HELPERS:
        print(f"[i] Helper d'authentification ignoré ({event_for_ai['proc_name']})")
        return jsonify({"status": "ignored", "reason": "auth helper"}), 200

    # 6d. Ignore container startup noise (entrypoint scripts as parent)
    parent = str(event_for_ai["parent_process"] or "")
    if ENTRYPOINT_PARENT_RE.match(parent):
        print(
            f"[i] Script de démarrage conteneur ignoré "
            f"(parent={parent}) | {event_for_ai['proc_name']}"
        )
        return jsonify({"status": "ignored", "reason": "entrypoint startup"}), 200

    # 7. AI prediction
    try:
        prediction = engine.predict(event_for_ai, history_df=df_history)
        score = prediction.get("combined_score", 0)
    except Exception as e:
        print(f"[!] Erreur pendant la prédiction IA : {e}")
        return jsonify(
            {"status": "error", "message": "AI prediction failed"}
        ), 500

    # 8. Prometheus AI score
    AI_ANOMALY_SCORE.labels(
        user=str(event_for_ai["user"]),
        pod=str(event_for_ai["pod"]),
        rule=str(event_for_ai["rule"]),
    ).set(score)

    # 9. Classify alert severity
    if score >= 70:
        AI_ALERTS_TOTAL.labels(severity="critical").inc()
    elif score >= 45:
        AI_ALERTS_TOTAL.labels(severity="moderate").inc()
    elif score >= 20:
        AI_ALERTS_TOTAL.labels(severity="suspect").inc()

    # 10. Display detection result
    print(f"\n[+] Event | {event_for_ai['rule']} | dur={duration_ms:.1f}ms")
    print(
        f"    User={event_for_ai['user']} "
        f"UID={event_for_ai['user_uid']} "
        f"Pod={event_for_ai['pod']}"
        f"{'' if uid_present else '  (user.uid absent de la règle Falco !)'}"
    )
    print(
        f"    Cmd={str(event_for_ai['command'])[:90]} | "
        f"proc={event_for_ai['proc_name']} parent={event_for_ai['parent_process']}"
    )
    print(
        f"    IA {prediction.get('status', 'unknown')} "
        f"score={score:.1f} "
        f"UBA={prediction.get('uba_score', 0):.1f} "
        f"tz={event_for_ai['timestamp']}"
    )
    print(f"    UBA reasons={prediction.get('uba_reasons', [])}")

    # 11. REMEDIATION
    if score >= 70:
        print(f"[!] Score critique ({score:.1f}) -> déclenchement de la remédiation.")

        try:
            remed_success, remed_msg, details = trigger_remediation(data, prediction)
        except Exception as e:
            print(f"[!] Erreur remédiation : {e}")
            remed_success = False
            remed_msg = str(e)
            details = {}

        # Already isolated: stop here (idempotency)
        if details.get("already_isolated"):
            print("[i] Pod déjà isolé — remédiation, Jira et mail arrêtés.")
            REMEDIATION_TOTAL.labels(status="already_isolated").inc()

        else:
            REMEDIATION_TOTAL.labels(
                status="success" if remed_success else "failed"
            ).inc()

            # Jira ticket
            try:
                ticket = create_jira_ticket(event_for_ai, prediction, remed_msg)

                if ticket:
                    JIRA_TICKETS_TOTAL.labels(
                        status="reused" if ticket.get("reused") else "created"
                    ).inc()
                else:
                    JIRA_TICKETS_TOTAL.labels(status="skipped").inc()

            except Exception as e:
                print(f"[!] Erreur création Jira : {e}")
                ticket = None
                JIRA_TICKETS_TOTAL.labels(status="failed").inc()

            # Email alert
            try:
                send_gmail_alert(
                    event_for_ai, score, remed_success, remed_msg, ticket
                )
            except Exception as e:
                print(f"[!] Erreur envoi Email : {e}")

            # Incident + Jenkins
            if remed_success:
                try:
                    inc = create_incident(
                        data, event_for_ai, prediction, remed_msg, ticket
                    )
                    INCIDENTS_TOTAL.labels(status="created").inc()
                    trigger_jenkins(inc)
                except Exception as e:
                    print(f"[!] Erreur création incident / Jenkins : {e}")

    # 12. Extract additional features
    file_name, connection = extract_file_and_connection(
        output_fields,
        event_for_ai["rule"],
    )

    # 13. Build CSV row (uses the RESOLVED user/uid)
    row = [
        data.get("time", ""),
        data.get("uuid", ""),
        data.get("priority", "Unknown"),
        data.get("rule", "Unknown"),
        event_for_ai["event_scope"],
        data.get("hostname", "unknown"),
        output_fields.get("k8s.ns.name") or effective_ns or "",
        output_fields.get("k8s.pod.name") or pod_name or "",
        output_fields.get("container.id", ""),
        output_fields.get("container.name", ""),
        output_fields.get("container.image.repository", ""),
        output_fields.get("container.image.tag", ""),
        event_for_ai["user"],
        event_for_ai["user_uid"],
        output_fields.get("proc.name", "unknown"),
        output_fields.get("proc.exepath", ""),
        output_fields.get("proc.pname", ""),
        output_fields.get("proc.cmdline", ""),
        output_fields.get("evt.type", ""),
        file_name or output_fields.get("fd.name", ""),
        connection,
        duration_ms,
    ]

    # 14. Persist event to CSV
    try:
        with open(REAL_DATA_PATH, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)

        _append_live_history(row)

    except Exception as e:
        print(f"[!] Erreur écriture CSV : {e}")

    # 15. Return response to Falco
    return jsonify(
        {
            "status": "success",
            "score": score,
            "ai_status": prediction.get("status", "unknown"),
        }
    ), 200


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    if FALCO_WEBHOOK_TOKEN:
        print("[+] Auth webhook Falco activée (FALCO_WEBHOOK_TOKEN).")
    else:
        print("[!] Auth webhook désactivée — définir FALCO_WEBHOOK_TOKEN hors lab.")

    start_http_server(COLLECTOR_METRICS_PORT)
    print(f"[+] Prometheus metrics : port {COLLECTOR_METRICS_PORT}")
    print(f"[+] Falco webhook : {COLLECTOR_BIND_HOST}:{COLLECTOR_WEBHOOK_PORT}")

    app.run(host=COLLECTOR_BIND_HOST, port=COLLECTOR_WEBHOOK_PORT)
