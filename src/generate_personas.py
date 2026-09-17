#!/usr/bin/env python3
"""Complète le dataset synthétique : personas admin/dev/service python."""
import csv
import os
import random
import uuid
from datetime import datetime, timedelta

import generate_smart_testdata as g

random.seed(42)

PYTHON_CMDS = [
    ("python -m app.worker", "python", "containerd-shim", "python", "472"),
    ("python /opt/app/main.py", "python", "containerd-shim", "python", "472"),
    ("python -c import time; time.sleep(1)", "python", "containerd-shim", "python", "472"),
]


def _utc_stamp(hour_utc, minute=None):
    day = random.randint(14, 20)
    m = minute if minute is not None else random.randint(0, 59)
    ts = datetime(2026, 8, day, hour_utc, m, random.randint(0, 59))
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def extra_events():
    events = []
    for _ in range(200):
        evs = g.generate_session([random.choice(PYTHON_CMDS)])
        events.extend(evs)

    for _ in range(60):
        ev = g.generate_event(
            ("cat /etc/shadow", "cat", "sh", "admin", "1000"),
            "Baseline normal activity demo-app",
            "Informational",
            file="/etc/shadow",

        )
        # 14h Africa/Tunis = 13h UTC
        ev["timestamp"] = _utc_stamp(13)
        events.append(ev)

    for _ in range(40):
        ev = g.generate_event(
            ("cat /etc/nginx/nginx.conf", "cat", "sh", "admin", "1000"),
            "Baseline normal activity demo-app",
            "Informational",
            file="/etc/nginx/nginx.conf",
        )
        ev["timestamp"] = _utc_stamp(random.choice([8, 10, 12, 14, 16]) - 1)
        events.append(ev)

    return events


def main():
    g.main()
    extras = extra_events()
    path = g.OUTPUT_PATH
    fieldnames = [
        "timestamp", "uuid", "priority", "rule", "event_scope", "node", "namespace",
        "pod", "container_id", "container_name", "image", "image_tag", "user", "user_uid",
        "proc_name", "proc_exepath", "parent_process", "command",
        "event_type", "file", "connection", "command_duration_ms",
    ]
    existing = []
    with open(path, newline="", encoding="utf-8") as f:
        existing = list(csv.DictReader(f))
    all_events = existing + extras
    all_events.sort(key=lambda x: x["timestamp"])
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_events)
    print(f"[+] Dataset synthétique enrichi : {len(all_events)} events ({len(extras)} personas)")


if __name__ == "__main__":
    main()
