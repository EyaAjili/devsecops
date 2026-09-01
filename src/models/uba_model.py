import os
import json
import pickle
import numpy as np
import pandas as pd
from collections import Counter
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from config.settings import PROFILE_DIR, MODEL_DIR
from core.features import extract_verb, target_domain, domain_to_score
from core.time_features import temporal_features, parse_duration_ms
from core.iocs_loader import (
    resolve_uid_from_role, SENSITIVE_PATHS, PRIVESC_VERBS,
    PACKAGE_VERBS, NETWORK_VERBS, RECON_VERBS, MALICIOUS_DOMAINS
)


def build_hourly_histogram(user_df):
    hist = np.zeros(24)
    for h in user_df["hour"]:
        hist[int(h) % 24] += 1
    total = hist.sum()
    if total > 0:
        hist = hist / total
    return hist.tolist()


class UBAModel:
    def __init__(self):
        self.profiles = {}
        self.models = {}

    def is_evident_anomaly(self, row):
        cmd = str(row.get("command", ""))
        verb = extract_verb(cmd)
        domain = target_domain(cmd)
        if domain == "external_malicious" or any(s in str(row.get("file", "")) for s in SENSITIVE_PATHS) or verb in PRIVESC_VERBS:
            return True
        return False

    def build_profile(self, df, user_uid):
        user_df = df[df["user_uid"].astype(str) == str(user_uid)].copy()
        if len(user_df) < 3:
            return None
        user_df["is_evident_anomaly"] = user_df.apply(self.is_evident_anomaly, axis=1).astype(int)
        normal_df = user_df[user_df["is_evident_anomaly"] == 0]
        profile = {
            "user_uid": user_uid,
            "user_name": str(user_df["user"].iloc[0]),
            "total_events": len(user_df),
            "hourly_histogram": build_hourly_histogram(normal_df if len(normal_df) > 0 else user_df),
            "verbs": [v for v, _ in Counter(user_df["command_verb"]).most_common(10)],
            "domains": [d for d, _ in Counter(user_df["target_domain"]).most_common()],
            "sensitive_rate": float(user_df["is_sensitive_file"].mean()),
            "pipe_rate": float(user_df["has_pipe"].mean()),
            "redirect_rate": float(user_df["has_redirect"].mean()),
            "cmd_len_mean": float(user_df["command_length"].mean()),
            "cmd_len_std": float(user_df["command_length"].std()) if user_df["command_length"].std() > 0 else 1.0,
            "timezone": "Africa/Tunis",
        }
        return profile

    def train_all_profiles(self, df):
        print("\n[COUCHE 2] Construction des profils UBA (heures Africa/Tunis)...")
        df = df.copy()
        tf = df["timestamp"].apply(temporal_features)
        df["hour"] = tf.apply(lambda t: t["hour_of_day"])
        df["day_of_week"] = tf.apply(lambda t: t["day_of_week"])
        df["is_off_hours"] = tf.apply(lambda t: t["is_off_hours"])
        df["command_verb"] = df["command"].apply(extract_verb)
        df["target_domain"] = df["command"].apply(target_domain)
        df["command_length"] = df["command"].str.len().fillna(0)
        df["is_sensitive_file"] = df["file"].apply(lambda f: any(s in str(f) for s in SENSITIVE_PATHS)).astype(int)
        df["has_pipe"] = df["command"].str.contains(r"\|", na=False).astype(int)
        df["has_redirect"] = df["command"].str.contains(r">|>>", na=False).astype(int)
        if "command_duration_ms" not in df.columns:
            df["command_duration_ms"] = 0.0
        df["command_duration_ms"] = df["command_duration_ms"].apply(parse_duration_ms)

        os.makedirs(MODEL_DIR, exist_ok=True)
        for uid in df["user_uid"].astype(str).unique():
            profile = self.build_profile(df, uid)
            if profile:
                self.profiles[uid] = profile
                user_df = df[df["user_uid"].astype(str) == uid]
                if len(user_df) >= 10:
                    X = user_df[[
                        "hour", "day_of_week", "command_length", "is_sensitive_file",
                        "has_pipe", "has_redirect", "is_off_hours", "command_duration_ms",
                    ]].values
                    scaler = StandardScaler()
                    Xs = scaler.fit_transform(X)
                    model = IsolationForest(contamination=0.15, random_state=42)
                    model.fit(Xs)
                    self.models[uid] = (model, scaler)
                    with open(os.path.join(MODEL_DIR, f"uba_if_{uid}.pkl"), "wb") as f:
                        pickle.dump((model, scaler), f)
                with open(os.path.join(PROFILE_DIR, f"uba_{uid}.json"), "w") as f:
                    json.dump(profile, f, indent=2, default=str)
                print(f"    Profil uid={uid} : {profile['total_events']} events, verbes={profile['verbs'][:3]}")
        return self

    def load(self):
        if os.path.isdir(PROFILE_DIR):
            for f in os.listdir(PROFILE_DIR):
                if f.endswith(".json"):
                    with open(os.path.join(PROFILE_DIR, f), "r") as file:
                        p = json.load(file)
                        self.profiles[str(p["user_uid"]).replace(".0", "")] = p
        if os.path.isdir(MODEL_DIR):
            for f in os.listdir(MODEL_DIR):
                if f.startswith("uba_if_") and f.endswith(".pkl"):
                    uid = f[len("uba_if_"):-4]
                    with open(os.path.join(MODEL_DIR, f), "rb") as file:
                        self.models[uid] = pickle.load(file)

    def score(self, event_dict):
        uid = str(event_dict.get("user_uid", "0")).replace(".0", "")
        if uid in ("nan", "NaN", "NAN", "None", "none", ""):
            uid = resolve_uid_from_role(str(event_dict.get("user", "root")).lower())

        profile = self.profiles.get(uid)
        if not profile:
            return 50.0, ["Utilisateur inconnu"]

        tf = temporal_features(event_dict.get("timestamp"))
        hour = tf["hour_of_day"]
        cmd = str(event_dict.get("command", ""))
        verb = extract_verb(cmd)
        domain = target_domain(cmd)
        duration_ms = parse_duration_ms(
            event_dict.get("command_duration_ms"),
            event_dict.get("evt.duration"),
            event_dict.get("proc.duration"),
        )

        score = 0.0
        reasons = []

        hist = profile.get("hourly_histogram", np.zeros(24))
        freq = hist[int(hour) % 24] if isinstance(hist, list) else 1.0
        if freq < 0.01:
            score += 25
            reasons.append(f"Heure inhabituelle ({hour}h Africa/Tunis)")
        if tf["is_off_hours"]:
            score += 10
            reasons.append(f"Hors horaires métier 08h–18h Tunis (heure={hour})")

        if verb not in profile["verbs"]:
            score += 30
            reasons.append(f"Verbe jamais utilisé par {profile['user_name']}: {verb}")

        if domain == "external_malicious":
            score += 50
            reasons.append("Domaine malveillant")
        elif domain not in profile["domains"] and domain != "none":
            score += 15
            reasons.append(f"Domaine nouveau pour {profile['user_name']}")

        if any(s in str(event_dict.get("file", "")) for s in SENSITIVE_PATHS) and profile["sensitive_rate"] < 0.01:
            score += 40
            reasons.append("Fichier sensible (jamais lu avant par cet utilisateur)")

        if duration_ms >= 3000:
            score += 15
            reasons.append(f"Durée d'exécution longue ({duration_ms:.0f} ms)")

        if uid in self.models:
            model, scaler = self.models[uid]
            X = np.array([[
                hour, tf["day_of_week"], len(cmd),
                1 if any(s in str(event_dict.get("file", "")) for s in SENSITIVE_PATHS) else 0,
                1 if "|" in cmd else 0, 1 if ">" in cmd else 0,
                tf["is_off_hours"], duration_ms,
            ]])
            try:
                if model.predict(scaler.transform(X))[0] == -1:
                    score += 30
                    reasons.append("IsolationForest : anomalie comportementale")
            except Exception:
                pass

        return score, reasons
