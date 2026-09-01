import re
import pandas as pd
from core.iocs_loader import (
    INTERNAL_INDICATORS, MALICIOUS_DOMAINS, NETWORK_VERBS,
    SUSPICIOUS_KEYWORDS, SUSPICIOUS_EXTS
)
from core.time_features import parse_duration_ms

SHELL_RE = re.compile(r"^(sh|bash|runc|sudo)\s+-c\s+", re.IGNORECASE)

# Vecteur couche 1 (ordre fixe — doit matcher le pickle après train.py)
FEATURE_COLS = [
    "hour_of_day",
    "day_of_week",
    "is_weekend",
    "is_off_hours",
    "timestamp_has_tz",
    "command_length",
    "command_arg_count",
    "command_duration_ms",
    "is_long_runtime",
    "has_pipe",
    "has_redirect",
    "has_dollar_subshell",
    "has_suspicious_keyword",
    "has_suspicious_extension",
    "is_sensitive_file",
    "is_shell_spawned",
    "has_indirection",
    "event_count_5min",
    "command_verb_enc",
    "target_domain_enc",
]


def extract_verb(cmd):
    if pd.isna(cmd):
        return "unknown"
    cleaned = SHELL_RE.sub("", str(cmd).strip())
    return cleaned.split()[0] if cleaned.split() else "unknown"


def target_domain(cmd):
    cmd = str(cmd)
    for ind in INTERNAL_INDICATORS:
        if ind in cmd:
            return "internal"
    for domain in MALICIOUS_DOMAINS:
        if domain in cmd:
            return "external_malicious"
    if any(v in cmd for v in NETWORK_VERBS):
        return "external_unknown"
    return "none"


def has_suspicious_keyword(cmd):
    return int(any(kw in str(cmd).lower() for kw in SUSPICIOUS_KEYWORDS))


def has_suspicious_extension(cmd):
    return int(any(ext in str(cmd) for ext in SUSPICIOUS_EXTS))


def domain_to_score(domain):
    return {"none": 0, "internal": 1, "external_unknown": 3, "external_malicious": 4}.get(domain, 2)


def command_duration_features(event_or_row):
    ms = parse_duration_ms(
        event_or_row.get("command_duration_ms") if hasattr(event_or_row, "get") else None,
        event_or_row.get("duration_ms") if hasattr(event_or_row, "get") else None,
        event_or_row.get("evt.duration") if hasattr(event_or_row, "get") else None,
        event_or_row.get("proc.duration") if hasattr(event_or_row, "get") else None,
    )
    return {
        "command_duration_ms": ms,
        "is_long_runtime": 1 if ms >= 3000 else 0,
    }


def extract_file_and_connection(output_fields, rule):
    fd_name = output_fields.get("fd.name") or ""
    event_type = output_fields.get("evt.type") or ""
    file_name = ""
    connection = ""
    filesystem_events = {"open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat"}
    network_events = {"connect", "accept", "accept4", "sendto", "recvfrom"}
    if event_type in filesystem_events:
        file_name = fd_name
    elif event_type in network_events:
        connection = fd_name
    elif ("connection" in str(rule).lower() or "network" in str(rule).lower() or "outbound" in str(rule).lower()):
        connection = fd_name
    return file_name, connection
