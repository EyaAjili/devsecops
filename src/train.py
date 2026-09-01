#!/usr/bin/env python3
import os
import pandas as pd
from config.settings import REAL_DATA_PATH, SYNTH_DATA_PATH
from models.hybrid_engine import HybridEngine

def main():
    print("[+] Chargement des datasets...")
    dfs = []
    if os.path.exists(REAL_DATA_PATH): dfs.append(pd.read_csv(REAL_DATA_PATH))
    if os.path.exists(SYNTH_DATA_PATH): dfs.append(pd.read_csv(SYNTH_DATA_PATH))
    
    if not dfs:
        print("[-] Erreur : Aucun dataset trouvé.")
        return

    df = pd.concat(dfs, ignore_index=True)
    df["user_uid"] = df["user_uid"].astype(str).str.replace(r"\.0$", "", regex=True)
    df = df[df["user_uid"] != "nan"].copy()

    print(f"[+] Dataset prêt : {len(df)} événements fusionnés.")

    engine = HybridEngine()
    engine.train(df)

    print("\n[+] Entraînement terminé avec succès ! Modèles et profils sauvegardés.")

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    main()

