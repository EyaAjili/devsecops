"""Horodatage et durée d'exécution pour le modèle IA.

Falco envoie `time` en RFC3339 (souvent avec Z = UTC). Sans conversion,
hour_of_day serait l'heure UTC, pas l'heure métier du lab (Tunisie).
Africa/Tunis = UTC+1 toute l'année (pas de DST).
"""
import os
import re
import pandas as pd

LAB_TIMEZONE = os.environ.get("LAB_TIMEZONE", "Africa/Tunis")
BUSINESS_HOUR_START = int(os.environ.get("BUSINESS_HOUR_START", "8"))
BUSINESS_HOUR_END = int(os.environ.get("BUSINESS_HOUR_END", "18"))

_TZ_SUFFIX = re.compile(r"(Z|[+-]\d{2}:?\d{2})$", re.IGNORECASE)


def timestamp_has_timezone(raw):
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return 0
    s = str(raw).strip()
    return 1 if _TZ_SUFFIX.search(s) else 0


def to_lab_local(raw):
    """Parse any Falco/CSV timestamp → Timestamp tz-aware in LAB_TIMEZONE, or NaT."""
    ts = pd.to_datetime(raw, errors="coerce", utc=False)
    if pd.isna(ts):
        return pd.NaT
    if getattr(ts, "tzinfo", None) is None:
        # Naïf : Falco/CSV sans offset → on suppose UTC (convention RFC3339 sans Z rare)
        ts = ts.tz_localize("UTC")
    else:
        ts = ts.tz_convert("UTC")
    try:
        return ts.tz_convert(LAB_TIMEZONE)
    except Exception:
        return ts.tz_convert("UTC") + pd.Timedelta(hours=1)


def temporal_features(raw):
    local = to_lab_local(raw)
    has_tz = timestamp_has_timezone(raw)
    if pd.isna(local):
        return {
            "hour_of_day": 12,
            "day_of_week": 0,
            "is_weekend": 0,
            "is_off_hours": 0,
            "timestamp_has_tz": has_tz,
            "timestamp_local": pd.NaT,
        }
    hour = int(local.hour)
    day = int(local.dayofweek)
    off = 1 if (hour < BUSINESS_HOUR_START or hour >= BUSINESS_HOUR_END) else 0
    return {
        "hour_of_day": hour,
        "day_of_week": day,
        "is_weekend": 1 if day in (5, 6) else 0,
        "is_off_hours": off,
        "timestamp_has_tz": has_tz,
        "timestamp_local": local,
    }


def parse_duration_ms(*values):
    """Falco evt.duration / proc.duration : ns, ms, '1.2ms', ou secondes."""
    best = 0.0
    for value in values:
        if value is None or (isinstance(value, float) and pd.isna(value)):
            continue
        s = str(value).strip().lower()
        if not s or s in ("nan", "none", "null"):
            continue
        ms = 0.0
        try:
            if s.endswith("ns"):
                ms = float(s[:-2]) / 1e6
            elif s.endswith("us") or s.endswith("µs"):
                ms = float(s[:-2]) / 1e3
            elif s.endswith("ms"):
                ms = float(s[:-2])
            elif s.endswith("s"):
                ms = float(s[:-1]) * 1000.0
            else:
                n = float(s)
                ms = n / 1e6 if n > 1e6 else n
        except ValueError:
            continue
        if ms > best:
            best = ms
    return float(min(max(best, 0.0), 120000.0))
