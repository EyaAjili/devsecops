import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode

from config.settings import (
    JIRA_API_TOKEN,
    JIRA_BASE_URL,
    JIRA_EMAIL,
    JIRA_ISSUE_TYPE,
    JIRA_PROJECT_KEY,
)


def _auth_header():
    token = b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    return f"Basic {token}"


def _request(method, path, payload=None, query=None):
    url = f"{JIRA_BASE_URL}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": _auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def _adf_paragraph(text):
    return {
        "type": "paragraph",
        "content": [{"type": "text", "text": text or "-"}],
    }


def _issue_browse_url(key):
    return f"{JIRA_BASE_URL}/browse/{key}"


def _find_open_ticket(pod_name):
    jql = (
        f'project = "{JIRA_PROJECT_KEY}" AND labels = "auto-quarantine" '
        f'AND summary ~ "\\"{pod_name}\\"" AND statusCategory != Done'
    )
    try:
        data = _request(
            "GET",
            "/rest/api/3/search/jql",
            query={"jql": jql, "maxResults": "1", "fields": "key,summary"},
        )
        issues = data.get("issues") or []
        if issues:
            key = issues[0]["key"]
            return {"key": key, "url": _issue_browse_url(key), "reused": True}
    except urllib.error.HTTPError:
        try:
            data = _request(
                "GET",
                "/rest/api/3/search",
                query={"jql": jql, "maxResults": "1", "fields": "summary"},
            )
            issues = data.get("issues") or []
            if issues:
                key = issues[0]["key"]
                return {"key": key, "url": _issue_browse_url(key), "reused": True}
        except urllib.error.HTTPError:
            return None
    return None


def create_jira_ticket(event, prediction, remediation_msg):
    """Create (or reuse) a Jira issue. Returns dict or None if Jira is not configured / down."""
    if not (JIRA_BASE_URL and JIRA_EMAIL and JIRA_API_TOKEN and JIRA_PROJECT_KEY):
        print("[!] Jira ignoré : définir JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY")
        return None

    pod = str(event.get("pod", "unknown"))
    score = prediction.get("combined_score", 0)
    rule = str(prediction.get("rule") or event.get("rule") or "unknown")

    existing = _find_open_ticket(pod)
    if existing:
        print(f"[+] Jira : ticket ouvert réutilisé {existing['key']}")
        return existing

    summary = f"[DevSecOps] Score {score:.0f} — pod {pod} — {rule}"[:255]
    description = {
        "type": "doc",
        "version": 1,
        "content": [
            _adf_paragraph("Incident généré automatiquement par le collector IA."),
            _adf_paragraph(f"Utilisateur : {event.get('user')} (uid={event.get('user_uid')})"),
            _adf_paragraph(f"Pod : {pod}"),
            _adf_paragraph(f"Règle Falco : {rule}"),
            _adf_paragraph(f"Commande : {event.get('command')}"),
            _adf_paragraph(
                f"Score combiné : {score:.1f}/100 | global={prediction.get('global_score', 0):.1f} "
                f"| UBA={prediction.get('uba_score', 0):.1f} | arbitrage={prediction.get('arbitrage')}"
            ),
            _adf_paragraph(f"Remédiation Cilium : {remediation_msg}"),
            _adf_paragraph(
                "Le pod porte le label quarantine=true. La CiliumNetworkPolicy "
                "demo-app/quarantine-policy drop ingress+egress (entities=all). "
                "Le process est conservé pour forensics ; un replica sain a été scalé."
            ),
        ],
    }

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary,
            "issuetype": {"name": JIRA_ISSUE_TYPE},
            "labels": ["devsecops", "falco", "auto-quarantine", "cilium"],
            "description": description,
        }
    }

    try:
        created = _request("POST", "/rest/api/3/issue", payload=payload)
        key = created.get("key")
        if not key:
            print(f"[!] Jira : réponse inattendue {created}")
            return None
        result = {"key": key, "url": _issue_browse_url(key), "reused": False}
        print(f"[+] Jira : ticket créé {key} → {result['url']}")
        return result
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        print(f"[!] Jira HTTP {e.code} : {err[:500]}")
        return None
    except Exception as e:
        print(f"[!] Jira indisponible : {e}")
        return None
