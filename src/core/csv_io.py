"""Lecture / réparation du CSV Falco (21 vs 22 colonnes)."""
import csv
import os

import pandas as pd

from config.settings import FALCO_CSV_COLUMNS


def load_falco_csv(path):
    """Charge le dataset live même si l'en-tête n'a pas encore command_duration_ms."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return pd.DataFrame(columns=FALCO_CSV_COLUMNS)

        has_duration = "command_duration_ms" in header
        name_to_idx = {name: i for i, name in enumerate(header)}
        rows = []
        for raw in reader:
            if not raw or all(not str(c).strip() for c in raw):
                continue
            mapped = []
            for col in FALCO_CSV_COLUMNS:
                if col in name_to_idx and name_to_idx[col] < len(raw):
                    mapped.append(raw[name_to_idx[col]])
                elif col == "command_duration_ms" and not has_duration and len(raw) > len(header):
                    mapped.append(raw[-1])
                else:
                    mapped.append("")
            rows.append(mapped)

    df = pd.DataFrame(rows, columns=FALCO_CSV_COLUMNS)
    df["user_uid"] = df["user_uid"].astype(str).str.replace(r"\.0$", "", regex=True)
    return df


def repair_falco_csv(path):
    """Réécrit le fichier avec l'en-tête canonique à 22 colonnes (évite l'erreur pandas)."""
    if not os.path.exists(path):
        return
    df = load_falco_csv(path)
    tmp = path + ".tmp"
    df.to_csv(tmp, index=False)
    os.replace(tmp, path)
    return df
