#!/usr/bin/env python3
"""Entraînement (charge le CSV live même s'il mélange 21 et 22 colonnes)."""

import os
import warnings

import pandas as pd

from config.settings import REAL_DATA_PATH, SYNTH_DATA_PATH
from core.csv_io import load_falco_csv, repair_falco_csv
from models.engine import HybridEngine


def main():
    print("[+] Chargement des datasets...")

    dfs = []

    if os.path.exists(REAL_DATA_PATH):
        print("[+] Réparation CSV live (colonnes 21/22)...")
        repair_falco_csv(REAL_DATA_PATH)
        dfs.append(load_falco_csv(REAL_DATA_PATH))

    if os.path.exists(SYNTH_DATA_PATH):
        dfs.append(pd.read_csv(SYNTH_DATA_PATH))

    if not dfs:
        print("[-] Erreur : Aucun dataset trouvé.")
        return

    # Fusion des datasets
    df = pd.concat(dfs, ignore_index=True)

    # Filtrage des événements sans pod valide
    df = df[
        df["pod"].notna()
        & (df["pod"] != "")
        & (df["pod"] != "unknown")
    ].copy()

    print(
        f"[+] Après filtrage host (pod vide) : "
        f"{len(df)} événements restants."
    )

    # Nettoyage de user_uid
    df["user_uid"] = (
        df["user_uid"]
        .astype(str)
        .str.replace(r"\.0$", "", regex=True)
    )

    df = df[df["user_uid"] != "nan"].copy()
    df = df[df["user_uid"].str.strip() != ""].copy()

    print(f"[+] Dataset prêt : {len(df)} événements fusionnés.")

    # Entraînement du moteur hybride
    engine = HybridEngine()
    engine.train(df)

    print(
        "\n[+] Entraînement terminé avec succès ! "
        "Modèles et profils sauvegardés."
    )


if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    main()
