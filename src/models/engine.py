from models.global_model import GlobalModel
from models.uba_model import UBAModel
from core.features import extract_verb, target_domain, is_sensitive_target, count_events_5min
from core.iocs_loader import RECON_VERBS, resolve_uid_from_role
from core.time_features import temporal_features


def _status_from_score(combined):
    if combined >= 70:
        return "🚨 ANOMALIE CRITIQUE"
    if combined >= 45:
        return "⚠️ ANOMALIE MODÉRÉE"
    if combined >= 20:
        return "🔍 SUSPECT"
    return "✅ NORMAL"


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
        uba_score, uba_reasons = self.layer2.score(event_dict, history_df=history_df)
        uba_score = float(min(uba_score, 100.0))

        verb = extract_verb(str(event_dict.get("command", "")))
        domain = target_domain(str(event_dict.get("command", "")))
        sensitive = is_sensitive_target(event_dict)
        off_hours = bool(temporal_features(event_dict.get("timestamp"))["is_off_hours"])
        burst = count_events_5min(event_dict, history_df)
        ioc_fort = sensitive or domain == "external_malicious"

        combined = (global_score * 0.35) + (uba_score * 0.65)
        arbitrage = "Mix 35% RF + 65% UBA"

        if uba_score <= 5 and verb in RECON_VERBS and not ioc_fort:
            combined = min(combined, max(global_score * 0.12, uba_score))
            uba_reasons = list(uba_reasons) + ["Verbe de reconnaissance bénin (profil utilisateur)"]
            arbitrage = "UBA domine (recon bénin)"

        if uba_score < 22 and not off_hours and burst < 10:
            combined = min(combined, global_score * 0.40)
            arbitrage = "UBA contextuel (comportement habituel)"

        if not ioc_fort and burst < 15 and uba_score >= 40:
            combined = min(combined, 55.0)
            arbitrage = "UBA comportemental sans IOC fichier/réseau"

        if sensitive and (off_hours or burst >= 15) and uba_score >= 30:
            combined = max(combined, 75.0)
            arbitrage = "Fichier sensible + heure tardive ou burst 5 min"

        if domain == "external_malicious" and (sensitive or off_hours or burst >= 10):
            combined = max(combined, 85.0)
            arbitrage = "C2 / exfil + contexte hostile"

        status = _status_from_score(combined)

        raw_uid = str(event_dict.get("user_uid", "0")).replace(".0", "")
        display_uid = (
            resolve_uid_from_role(str(event_dict.get("user", "root")).lower())
            if raw_uid in ("nan", "NaN", "NAN", "None", "none", "")
            else raw_uid
        )

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
            "rule": str(event_dict.get("rule", "")),
        }
