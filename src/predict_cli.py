#!/usr/bin/env python3
import pandas as pd
from config.settings import REAL_DATA_PATH
from models.hybrid_engine import HybridEngine

def print_result(p):
    print(f"\n{'='*80}")
    print(f"  👤 {p['user']} (uid={p['uid']})  |  📜 {p['rule'][:40]}")
    print(f"  💻 {p['command']}")
    print(f"  📊 {p['status']}")
    print(f"  🔢 Score combiné: {p['combined_score']:.0f}/100")
    print(f"     → Global: {p['global_score']:.0f} | UBA: {p['uba_score']:.0f}")
    print(f"  ⚖️  Arbitrage: {p['arbitrage']}")
    print(f"  📋 Raisons:")
    print(f"     • {p['global_reason']}")
    for r in p['uba_reasons']:
        print(f"     • {r}")
    print(f"{'='*80}")

def main():
    engine = HybridEngine()
    engine.load()
    
    df_real = pd.read_csv(REAL_DATA_PATH)
    real_events = df_real.to_dict("records")
    
    print("\n[+] Démarrage de l'inférence sur quelques événements de test...")
    for ev in real_events[:5]:  # Test sur les 5 premiers événements
        p = engine.predict(ev, history_df=df_real)
        print_result(p)

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    main()

