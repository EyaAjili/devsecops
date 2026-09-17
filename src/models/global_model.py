import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import roc_auc_score, classification_report, confusion_matrix

from config.settings import MODEL_DIR
from core.features import (
    FEATURE_COLS,
    extract_verb,
    target_domain,
    has_suspicious_keyword,
    has_suspicious_extension,
    command_duration_features,
    count_events_5min,
)
from core.iocs_loader import SENSITIVE_PATHS, NETWORK_VERBS
from core.time_features import temporal_features, to_lab_local, parse_duration_ms

ANOMALY_RULES = {
    "Unexpected process spawned in application container",
    "Unexpected process spawned",
    "Read sensitive file untrusted",
    "Sensitive file access outside shadow",
    "Sensitive environment variable credential access",
    "Unexpected package manager execution",
    "Suspicious outbound connection",
    "Unexpected inbound connection on non-standard port",
    "Terminal shell in container",
    "Run shell untrusted",
}

# Bruit Kubernetes / hôte : ne pas les apprendre comme « attaque ».
NOISE_RULES = {
    "Drop and execute new binary in container",
    "Directory traversal monitored file read",
    "Contact K8S API Server From Container",
    "Baseline normal activity demo-app",
}


def label_is_anomaly(row):
    rule = str(row.get("rule", ""))
    cmd = str(row.get("command", ""))
    if rule in NOISE_RULES:
        return 0
    if rule == "Suspicious outbound connection":
        domain = target_domain(cmd)
        return 1 if domain in ("external_malicious", "external_unknown") else 0
    if rule in ANOMALY_RULES:
        return 1
    return 0


class GlobalModel:
    def __init__(self):
        self.model = None
        self.le_dict = {}
        self.feature_cols = list(FEATURE_COLS)

    def extract_features(self, df):
        df = df.copy()
        temporal = df["timestamp"].apply(temporal_features)
        df["hour_of_day"] = temporal.apply(lambda t: t["hour_of_day"])
        df["day_of_week"] = temporal.apply(lambda t: t["day_of_week"])
        df["is_weekend"] = temporal.apply(lambda t: t["is_weekend"])
        df["is_off_hours"] = temporal.apply(lambda t: t["is_off_hours"])
        df["timestamp_has_tz"] = temporal.apply(lambda t: t["timestamp_has_tz"])
        df["timestamp_dt"] = df["timestamp"].apply(to_lab_local)

        df["command"] = df["command"].fillna("").astype(str)
        df["command_verb"] = df["command"].apply(extract_verb)
        df["command_length"] = df["command"].str.len().fillna(0)
        df["command_arg_count"] = df["command"].str.split().str.len().fillna(0)
        df["has_pipe"] = df["command"].str.contains(r"\|", regex=True, na=False).astype(int)
        df["has_redirect"] = df["command"].str.contains(r">|>>", regex=True, na=False).astype(int)
        df["has_dollar_subshell"] = df["command"].str.contains(r"\$\(", regex=True, na=False).astype(int)
        df["has_suspicious_keyword"] = df["command"].apply(has_suspicious_keyword)
        df["has_suspicious_extension"] = df["command"].apply(has_suspicious_extension)
        df["target_domain"] = df["command"].apply(target_domain)

        if "command_duration_ms" not in df.columns:
            df["command_duration_ms"] = 0.0
        df["command_duration_ms"] = df.apply(
            lambda r: parse_duration_ms(r.get("command_duration_ms", 0)), axis=1
        )
        df["is_long_runtime"] = (df["command_duration_ms"] >= 3000).astype(int)

        df["file"] = df["file"].fillna("").astype(str)
        df["is_sensitive_file"] = df.apply(
            lambda r: int(any(s in f"{r.get('file', '')} {r.get('command', '')}" for s in SENSITIVE_PATHS)),
            axis=1,
        )
        df["proc_name"] = df["proc_name"].fillna("").astype(str) if "proc_name" in df.columns else ""
        df["parent_process"] = df["parent_process"].fillna("").astype(str) if "parent_process" in df.columns else ""
        df["is_shell_spawned"] = (
            df["proc_name"].isin(["sh", "bash", "zsh"])
            | df["parent_process"].isin(["runc", "sh", "bash"])
        ).astype(int)
        df["has_indirection"] = (
            (df["proc_name"] == "sh")
            & df["command_verb"].isin(list(NETWORK_VERBS) + ["cat", "ls"])
        ).astype(int)

        df["event_count_5min"] = 0
        for _, group in df.groupby("pod"):
            group = group.sort_values("timestamp_dt")
            times = group["timestamp_dt"]
            counts = []
            for t in times:
                if pd.isna(t):
                    counts.append(0)
                    continue
                window_start = t - pd.Timedelta(minutes=5)
                counts.append(int(((times >= window_start) & (times <= t)).sum()))
            df.loc[group.index, "event_count_5min"] = counts

        df["is_anomaly"] = df.apply(label_is_anomaly, axis=1).astype(int)
        return df

    def encode(self, df):
        for col in ["event_scope", "command_verb"]:
            if col in df.columns:
                le = LabelEncoder()
                df[col + "_enc"] = le.fit_transform(df[col].fillna("unknown").astype(str))
                self.le_dict[col] = le

        self.feature_cols = [c for c in FEATURE_COLS if c in df.columns]
        X = df[self.feature_cols].fillna(0)
        y = df["is_anomaly"].values if "is_anomaly" in df.columns else None
        return X, y

    def train(self, df):
        print("\n[COUCHE 1] Entraînement du modèle GLOBAL...")
        df = self.extract_features(df)
        X, y = self.encode(df)
        if len(X) < 10:
            raise ValueError("Dataset trop petit pour entraîner le modèle.")
        if len(np.unique(y)) < 2:
            raise ValueError("Le dataset doit contenir au moins une classe normale et une anomalie.")

        split_idx = int(len(X) * 0.75)
        X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
        y_train, y_test = y[:split_idx], y[split_idx:]
        print(f"\nDataset total : {len(X)}")
        print(f"Training      : {len(X_train)}")
        print(f"Testing       : {len(X_test)}")
        print("\nDistribution training :")
        print(pd.Series(y_train).value_counts().rename(index={0: "Normal", 1: "Anomalie"}))

        # Arbre volontairement peu profond : évite un ROC-AUC « parfait » qui recopie Falco.
        self.model = RandomForestClassifier(
            n_estimators=80, max_depth=4, min_samples_split=25, min_samples_leaf=12,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]
        print("\n========================================")
        print("       RANDOM FOREST RESULTS")
        print("========================================")
        print(classification_report(y_test, y_pred, labels=[0, 1], target_names=["Normal", "Anomalie"], zero_division=0))
        if len(np.unique(y_test)) == 2:
            print(f"ROC-AUC Global : {roc_auc_score(y_test, y_proba):.3f}")
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred, labels=[0, 1]))
        print("\nFeature Importance:")
        print(pd.Series(self.model.feature_importances_, index=self.feature_cols).sort_values(ascending=False))

        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(os.path.join(MODEL_DIR, "layer1_global.pkl"), "wb") as f:
            pickle.dump(self.model, f)
        with open(os.path.join(MODEL_DIR, "layer1_encoders.pkl"), "wb") as f:
            pickle.dump(self.le_dict, f)
        with open(os.path.join(MODEL_DIR, "layer1_feature_cols.pkl"), "wb") as f:
            pickle.dump(self.feature_cols, f)
        print("\n[OK] Modèle sauvegardé.")
        return self

    def load(self):
        with open(os.path.join(MODEL_DIR, "layer1_global.pkl"), "rb") as f:
            self.model = pickle.load(f)
        with open(os.path.join(MODEL_DIR, "layer1_encoders.pkl"), "rb") as f:
            self.le_dict = pickle.load(f)
        cols_path = os.path.join(MODEL_DIR, "layer1_feature_cols.pkl")
        if os.path.exists(cols_path):
            with open(cols_path, "rb") as f:
                self.feature_cols = pickle.load(f)
        else:
            self.feature_cols = [
    "hour_of_day", "day_of_week", "is_weekend", "command_length",
    "command_arg_count", "is_shell_spawned", "has_indirection",
    "event_count_5min", "command_verb_enc",
]
        return self

    def predict(self, event_dict, history_df=None):
        if self.model is None:
            self.load()

        tf = temporal_features(event_dict.get("timestamp"))
        cmd = str(event_dict.get("command", ""))
        dur = command_duration_features(event_dict)

        event_count_5min = count_events_5min(event_dict, history_df)

        proc_name = str(event_dict.get("proc_name", ""))
        parent_process = str(event_dict.get("parent_process", ""))
        file_value = str(event_dict.get("file", ""))
        verb = extract_verb(cmd)

        features = {
            **{k: tf[k] for k in ("hour_of_day", "day_of_week", "is_weekend", "is_off_hours", "timestamp_has_tz")},
            **dur,
            "command_length": len(cmd),
            "command_arg_count": len(cmd.split()),
            "has_pipe": 1 if "|" in cmd else 0,
            "has_redirect": 1 if ">" in cmd else 0,
            "has_dollar_subshell": 1 if "$(" in cmd else 0,
            "has_suspicious_keyword": has_suspicious_keyword(cmd),
            "has_suspicious_extension": has_suspicious_extension(cmd),
            "is_sensitive_file": 1 if any(s in f"{file_value} {cmd}" for s in SENSITIVE_PATHS) else 0,
            "is_shell_spawned": 1 if proc_name in ["sh", "bash", "zsh"] or parent_process in ["runc", "sh", "bash"] else 0,
            "has_indirection": 1 if proc_name == "sh" and verb in (list(NETWORK_VERBS) + ["cat", "ls"]) else 0,
            "event_count_5min": event_count_5min,
            "command_verb": verb,
            "target_domain": target_domain(cmd),
        }

        row = {}
        for feature in self.feature_cols:
            if not feature.endswith("_enc"):
                row[feature] = features.get(feature, 0)
        for col in ["command_verb", "target_domain"]:
            enc_col = col + "_enc"
            le = self.le_dict.get(col)
            value = features.get(col, "unknown")
            if le is not None:
                try:
                    row[enc_col] = le.transform([value])[0]
                except ValueError:
                    row[enc_col] = 0
            else:
                row[enc_col] = 0

        X = np.array([[row.get(f, 0) for f in self.feature_cols]])
        return float(self.model.predict_proba(X)[0][1])
