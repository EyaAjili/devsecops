
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "decision_table.txt"

# label (start of the line) -> expected status keyword
EXPECTED = {
    "Dev 1001 ls 14h": "NORMAL",
    "Dev 1001 shadow 14h": "MODÉRÉE",
    "Dev 1001 shadow 02h ": "CRITIQUE",
    "Dev 1001 shadow 02h 40/5min": "CRITIQUE",
    "Admin 1000 shadow 14h": "NORMAL",
    "Svc 472 python 14h": "NORMAL",
    "Svc 472 bash 02h": "MODÉRÉE",
    "Svc 472 bash+shadow+curl 02h": "CRITIQUE",
}
KEYWORDS = ("CRITIQUE", "MODÉRÉE", "SUSPECT", "NORMAL")

lines = open(path, encoding="utf-8").read().splitlines()
failures = []
for label, expected in EXPECTED.items():
    line = next((l for l in lines if l.startswith(label)), None)
    if line is None:
        failures.append(f"{label.strip()}: case missing from the table")
        continue
    # decision = text after the numeric columns, before the arbitrage
    decision = line.split("|")[0]
    found = next((k for k in KEYWORDS if k in decision), "?")
    status = "OK " if found == expected else "FAIL"
    print(f"[{status}] {label.strip():<32} expected={expected:<8} got={found}")
    if found != expected:
        failures.append(f"{label.strip()}: expected {expected}, got {found}")

if failures:
    sys.exit("SCENARIO GATE FAILED:\n  " + "\n  ".join(failures))
print(f"All {len(EXPECTED)} scenarios OK")
