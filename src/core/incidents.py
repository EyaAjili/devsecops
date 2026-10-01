import os, re, json, uuid, tempfile, threading, datetime
import requests
from config.settings import (
    INCIDENT_DIR, JENKINS_URL, JENKINS_USER, JENKINS_TOKEN,
    JENKINS_JOB, COLLECTOR_PUBLIC_URL,
)

_ID_RE = re.compile(r"^INC-\d{8}-[A-F0-9]{5}$")
_lock = threading.Lock()
os.makedirs(INCIDENT_DIR, exist_ok=True)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def new_incident_id():
    d = datetime.datetime.now(datetime.timezone.utc)
    return f"INC-{d:%Y%m%d}-{uuid.uuid4().hex[:5].upper()}"


def _path(iid):
    if not _ID_RE.match(iid):              # blocks path traversal like ../../etc/passwd
        raise ValueError("invalid incident id")
    return os.path.join(INCIDENT_DIR, f"{iid}.json")


def _write(inc):
    with _lock:
        fd, tmp = tempfile.mkstemp(dir=INCIDENT_DIR)
        with os.fdopen(fd, "w") as f:
            json.dump(inc, f, indent=2, default=str)   # default=str: numpy types in prediction
        os.replace(tmp, _path(inc["id"]))              # atomic write


def create_incident(data, event, prediction, remed_msg, ticket):
    of = data.get("output_fields", {})
    inc = {
        "id": new_incident_id(),
        "status": "QUARANTINED",
        "created_at": _now(),
        "pod": event["pod"],
        "user": event.get("user", "unknown"),
        "user_uid": event.get("user_uid", "0"),
        "command": (event.get("command", "") or "")[:500],
        "namespace": of.get("k8s.ns.name", ""),
        "image": f"{of.get('container.image.repository','')}:{of.get('container.image.tag','')}",
        "rule": event["rule"],
        "score": prediction.get("combined_score", 0),
        "action": "quarantine",
        "remediation_msg": remed_msg,
        "jira_key": (ticket or {}).get("key"),   # adapt if your ticket dict uses another field
        "falco_event": data,                     # raw Falco event
        "ai_result": prediction,                 # RF + IsolationForest + UBA
    }
    _write(inc)
    return inc


def load_incident(iid):
    with open(_path(iid)) as f:
        return json.load(f)


def update_status(iid, status, decision=None):
    inc = load_incident(iid)
    inc["status"] = status
    inc["decision"] = decision
    inc["updated_at"] = _now()
    _write(inc)
    return inc


def trigger_jenkins(inc):
    """Fire-and-forget. Never blocks the collector, never raises."""
    if not JENKINS_URL:
        return

    of = inc.get("falco_event", {}).get("output_fields", {})
    command = (of.get("proc.cmdline", "") or "")[:300]  # tronqué : limite pratique des paramètres Jenkins

    # Use the resolved user from the incident (already corrected
    # for `su` target attribution by the collector), not the raw
    # Falco output_fields which would report root for su commands.
    resolved_user = inc.get("user", of.get("user.name", "unknown"))
    resolved_uid = str(inc.get("user_uid", of.get("user.uid", "0")))

    # UBA details for enriched Slack alert
    ai_result = inc.get("ai_result", {})
    uba_score = f"{ai_result.get('uba_score', 0):.1f}"
    uba_reasons = " | ".join(ai_result.get("uba_reasons", [])) or "Aucune"
    global_score = f"{float(ai_result.get('global_score', 0)):.1f}"
    arbitrage = str(ai_result.get("arbitrage", "n/a"))

    def _call():
        try:
            r = requests.post(
                f"{JENKINS_URL}/job/{JENKINS_JOB}/buildWithParameters",
                auth=(JENKINS_USER, JENKINS_TOKEN),
                data={
                    "INCIDENT_ID": inc["id"], "NAMESPACE": inc["namespace"],
                    "POD": inc["pod"], "SCORE": f"{inc['score']:.1f}",
                    "IMAGE": inc["image"],
                    "COLLECTOR_URL": COLLECTOR_PUBLIC_URL,
                    "RULE": inc.get("rule", "unknown"),
                    "USER": resolved_user,
                    "UID": resolved_uid,
                    "COMMAND": command,
                    "UBA_SCORE": uba_score,
                    "UBA_REASONS": uba_reasons,
                    "GLOBAL_SCORE": global_score,
                    "ARBITRAGE": arbitrage,
                },
                timeout=5,
            )
            print(f"[+] Jenkins déclenché pour {inc['id']} (HTTP {r.status_code})")
        except Exception as e:
            print(f"[!] Jenkins injoignable : {e} (la quarantaine reste valide)")

    threading.Thread(target=_call, daemon=True).start()


