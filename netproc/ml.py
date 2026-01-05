import os
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.ensemble import RandomForestClassifier


DEFAULT_FEATURES = [
    "duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    "dst_port",
    "protocol",
]


def _prep_features(df: pd.DataFrame, features):
    X = df.copy()

    if "protocol" in X.columns:
        X["protocol"] = X["protocol"].fillna(0)
        X["protocol"] = pd.factorize(X["protocol"])[0]

    for c in features:
        if c not in X.columns:
            X[c] = 0
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0)

    return X[features].astype(float)


def train_or_load_model(model_path: str, train_csv=None, force_train=False):
    meta = {"features": DEFAULT_FEATURES}

    if (not force_train) and os.path.exists(model_path) and not train_csv:
        obj = joblib.load(model_path)
        return obj["model"], obj["meta"]

    if not train_csv:
        # bez danych uczących: trenujemy “baseline” na syntetyku (w raporcie opiszesz jako fallback)
        df = _make_synthetic_training()
    else:
        df = pd.read_csv(train_csv)

    y = df["label"].astype(int)
    X = _prep_features(df, meta["features"])

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=7, stratify=y)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=7,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(Xtr, ytr)

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump({"model": model, "meta": meta}, model_path)

    return model, meta


def predict_with_model(model, flows_df: pd.DataFrame, meta):
    X = _prep_features(flows_df, meta["features"])
    proba = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[:, 1]
    pred = model.predict(X)
    out = flows_df[["id", "src_ip", "dst_ip", "dst_port", "first_seen_ms"]].copy()
    out["ml_pred"] = pred
    out["ml_score"] = proba if proba is not None else np.nan
    return out


def evaluate_model(model, train_csv: str, meta):
    df = pd.read_csv(train_csv)
    y = df["label"].astype(int)
    X = _prep_features(df, meta["features"])
    pred = model.predict(X)

    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    tpr = tp / (tp + fn) if (tp + fn) else 0.0

    return {
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fpr), "tpr": float(tpr),
    }


def _make_synthetic_training(n=2000):
    rng = np.random.default_rng(7)
    df = pd.DataFrame({
        "duration_ms": rng.integers(1, 120000, size=n),
        "bidirectional_packets": rng.integers(1, 5000, size=n),
        "bidirectional_bytes": rng.integers(100, 5_000_000, size=n),
        "src2dst_packets": rng.integers(1, 3000, size=n),
        "src2dst_bytes": rng.integers(50, 4_000_000, size=n),
        "dst2src_packets": rng.integers(0, 3000, size=n),
        "dst2src_bytes": rng.integers(0, 4_000_000, size=n),
        "dst_port": rng.choice([53, 80, 443, 22, 3389, 445, 123], size=n),
        "protocol": rng.choice([6, 17], size=n),
    })

    # label: “podejrzane” gdy duże bytes i 443 lub 445/3389 spore
    label = (
        ((df["dst_port"] == 443) & (df["src2dst_bytes"] > 1_000_000)) |
        ((df["dst_port"].isin([445, 3389])) & (df["bidirectional_bytes"] > 500_000))
    ).astype(int)
    df["label"] = label
    return df
