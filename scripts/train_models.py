"""Train the URL classifier and write ai/models/url_model.pkl (+ model_config.json).

Offline / demo mode (synthetic data):
    python scripts/train_models.py

Real data (recommended for the report):
    python scripts/train_models.py --phishing-csv phishtank.csv --legit-csv tranco.csv
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from ai.url_detection.dataset import generate_synthetic, load_real_csvs  # noqa: E402
from ai.url_detection.features import FEATURE_NAMES, InvalidURLError, extract_features, normalize_url  # noqa: E402

MODEL_DIR = ROOT / "ai" / "models"


def build_matrix(df: pd.DataFrame):
    rows, labels = [], []
    for url, label in zip(df["url"], df["label"]):
        try:
            feats = extract_features(normalize_url(url))
        except InvalidURLError:
            continue
        rows.append([feats[n] for n in FEATURE_NAMES])
        labels.append(label)
    return np.array(rows), np.array(labels)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phishing-csv")
    ap.add_argument("--legit-csv")
    ap.add_argument("--n-synthetic", type=int, default=6000, help="URLs per class in synthetic mode")
    ap.add_argument("--limit", type=int, help="max rows per class when using real CSVs")
    args = ap.parse_args()

    if args.phishing_csv and args.legit_csv:
        df = load_real_csvs(args.phishing_csv, args.legit_csv, args.limit)
        data_source = "real"
    else:
        df = generate_synthetic(args.n_synthetic)
        data_source = "synthetic"
    print(f"Dataset ({data_source}): {len(df)} URLs  |  malicious: {int(df['label'].sum())}")

    X, y = build_matrix(df)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    model = RandomForestClassifier(
        n_estimators=300, min_samples_leaf=2, class_weight="balanced", n_jobs=-1, random_state=42
    )
    model.fit(X_tr, y_tr)

    proba = model.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
    metrics = {
        "precision": round(precision_score(y_te, pred), 4),
        "recall": round(recall_score(y_te, pred), 4),
        "f1": round(f1_score(y_te, pred), 4),
        "roc_auc": round(roc_auc_score(y_te, proba), 4),
        "false_positive_rate": round(fp / max(fp + tn, 1), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    print(json.dumps(metrics, indent=2))

    importances = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1])
    print("\nTop features:")
    for name, imp in importances[:8]:
        print(f"  {name:22s} {imp:.3f}")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "url_model.pkl")
    (MODEL_DIR / "model_config.json").write_text(json.dumps({
        "model": "RandomForestClassifier",
        "data_source": data_source,
        "train_size": int(len(y_tr)),
        "test_size": int(len(y_te)),
        "features": FEATURE_NAMES,
        "metrics": metrics,
        "feature_importances": {n: round(float(i), 4) for n, i in importances},
        "note": "Metrics on synthetic data are optimistic; retrain on PhishTank/Tranco for real figures."
        if data_source == "synthetic" else "Trained on real data.",
    }, indent=2))
    print(f"\nSaved model -> {MODEL_DIR / 'url_model.pkl'}")


if __name__ == "__main__":
    main()
