import json
import os
from config.settings import IOCS_PATH

def load_iocs():
    if not os.path.exists(IOCS_PATH):
        print(f"[!] Warning: Fichier IOC {IOCS_PATH} introuvable. Utilisation des valeurs par défaut.")
        return {}
    with open(IOCS_PATH, "r") as f:
        return json.load(f)

_IOCS = load_iocs()

MALICIOUS_DOMAINS = _IOCS.get("malicious_domains", [])
INTERNAL_INDICATORS = _IOCS.get("internal_indicators", [])
SENSITIVE_PATHS = _IOCS.get("sensitive_paths", [])
SUSPICIOUS_EXTS = _IOCS.get("suspicious_extensions", [])
SUSPICIOUS_KEYWORDS = _IOCS.get("suspicious_keywords", [])

RECON_VERBS = set(_IOCS.get("recon_verbs", []))
PRIVESC_VERBS = set(_IOCS.get("privesc_verbs", []))
PACKAGE_VERBS = set(_IOCS.get("package_verbs", []))
NETWORK_VERBS = set(_IOCS.get("network_verbs", []))
USER_ROLES = _IOCS.get("user_roles", {})

def resolve_uid_from_role(user_name):
    user_lower = str(user_name).lower()
    for role, data in USER_ROLES.items():
        if role == user_lower:
            uids = data.get("uids", [])
            return str(uids[0]) if uids else "0"
    return "0"

