
import os
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "train_report.txt"
min_recall = float(os.environ.get("MIN_RECALL", "0.75"))
min_auc = float(os.environ.get("MIN_AUC", "0.85"))

txt = open(path, encoding="utf-8").read()
m = re.search(r"Anomalie\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+\d+", txt)
a = re.search(r"ROC-AUC Global\s*:\s*([\d.]+)", txt)
if not m or not a:
    sys.exit("Unreadable report: 'Anomalie' line or ROC-AUC not found")

precision, recall, auc = float(m.group(1)), float(m.group(2)), float(a.group(1))
print(f"Anomalie: precision={precision} recall={recall} | ROC-AUC={auc}")
print(f"Thresholds: recall >= {min_recall}, ROC-AUC >= {min_auc}")

errors = []
if recall < min_recall:
    errors.append(f"recall {recall} < {min_recall}")
if auc < min_auc:
    errors.append(f"ROC-AUC {auc} < {min_auc}")
if errors:
    sys.exit("QUALITY GATE FAILED: " + "; ".join(errors))
print("Quality gate OK")
