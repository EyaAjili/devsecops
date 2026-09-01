from models.global_model import GlobalModel
from models.uba_model import UBAModel
from core.features import extract_verb
from core.iocs_loader import RECON_VERBS, resolve_uid_from_role

class HybridEngine:
    def __init__(self):
        self.layer1 = GlobalModel()
        self.layer2 = UBAModel()

    def train(self, df):
        self.layer1.train(df)
        self.layer2.train_all_profiles(df)
        return self

    def load(self):
        self.layer1.load()
        self.layer2.load()

    def predict(self, event_dict, history_df=None):
        global_proba = self.layer1.predict(event_dict, history_df=history_df)
        global_score = global_proba * 100

        # ARBITRAGE DYNAMIQUE
        if global_proba >= 0.80:
            combined, status, arbitrage = global_score, "🚨 ANOMALIE CRITIQUE", "Global seul"
            uba_score, uba_reasons = 0, ["Global tres confiant, pas besoin d'UBA"]
        elif global_proba <= 0.15:
            combined, status, arbitrage = global_score * 0.5, "✅ NORMAL", "Global seul"
            uba_score, uba_reasons = 0, ["Global tres confiant (normal)"]
        else:
            uba_score, uba_reasons = self.layer2.score(event_dict)
            verb = extract_verb(str(event_dict.get("command", "")))

            if uba_score <= 5 and verb in RECON_VERBS:
                combined = max(global_score * 0.12, uba_score)
                status = "✅ NORMAL" if combined < 15 else "🔍 SUSPECT"
                uba_reasons.append("Verbe de reconnaissance bénin (contexte utilisateur confirmé)")
                arbitrage = "UBA domine (recon bénin)"
            else:
                combined = (global_score * 0.3) + (uba_score * 0.7)
                status = "🚨 ANOMALIE CRITIQUE" if combined >= 70 else "⚠️ ANOMALIE MODÉRÉE" if combined >= 45 else "🔍 SUSPECT" if combined >= 20 else "✅ NORMAL"
                arbitrage = "UBA arbitrage"

        raw_uid = str(event_dict.get("user_uid", "0")).replace(".0", "")
        display_uid = resolve_uid_from_role(str(event_dict.get("user", "root")).lower()) if raw_uid in ("nan", "NaN", "NAN", "None", "none", "") else raw_uid

        return {
            "status": status,
            "combined_score": combined,
            "global_score": global_score,
            "uba_score": uba_score,
            "global_reason": f"Score global: {global_proba:.1%}",
            "uba_reasons": uba_reasons,
            "arbitrage": arbitrage,
            "user": str(event_dict.get("user", "root")),
            "uid": display_uid,
            "command": str(event_dict.get("command", ""))[:55],
            "rule": str(event_dict.get("rule", ""))
        }

