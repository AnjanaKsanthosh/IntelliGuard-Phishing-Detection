"""
Train IntelliGuard's URL-text classifier using the UCI PhiUSIIL phishing URL dataset.
Dataset labels: 1 = legitimate, 0 = phishing.
Internet is required for the first dataset download.
"""
from pathlib import Path
import json
import joblib
import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "url_model.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"

def main():
    print("Downloading UCI PhiUSIIL dataset (first run requires internet)...")
    dataset = fetch_ucirepo(id=967)
    X = dataset.data.features
    y = dataset.data.targets

    # Locate the URL column and target column without assuming capitalization.
    url_col = next((c for c in X.columns if str(c).strip().lower() == "url"), None)
    if url_col is None:
        raise ValueError(f"Could not find URL column. Available columns: {list(X.columns)}")

    target_col = next((c for c in y.columns if str(c).strip().lower() == "label"), None)
    if target_col is None:
        if len(y.columns) == 1:
            target_col = y.columns[0]
        else:
            raise ValueError(f"Could not identify label column: {list(y.columns)}")

    frame = pd.DataFrame({
        "url": X[url_col].astype(str),
        "label": pd.to_numeric(y[target_col], errors="coerce")
    }).dropna()
    frame = frame[frame["url"].str.startswith(("http://", "https://"), na=False)]
    frame = frame[frame["label"].isin([0, 1])]
    frame = frame.drop_duplicates(subset=["url"])

    if frame["label"].nunique() != 2 or len(frame) < 100:
        raise ValueError("Dataset did not contain enough valid examples from both classes.")

    # UCI PhiUSIIL: 0 = phishing, 1 = legitimate.
    X_train, X_test, y_train, y_test = train_test_split(
        frame["url"], frame["label"].astype(int),
        test_size=0.20, random_state=42, stratify=frame["label"].astype(int)
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char", ngram_range=(3, 5),
            min_df=2, max_features=180000, sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            max_iter=1200, class_weight="balanced", random_state=42
        ))
    ])

    print(f"Training on {len(X_train):,} URLs; testing on {len(X_test):,} URLs...")
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    metrics = {
        "dataset": "UCI PhiUSIIL Phishing URL Dataset (ID 967)",
        "samples": int(len(frame)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_phishing": float(precision_score(y_test, predictions, pos_label=0, zero_division=0)),
        "recall_phishing": float(recall_score(y_test, predictions, pos_label=0, zero_division=0)),
        "f1_phishing": float(f1_score(y_test, predictions, pos_label=0, zero_division=0)),
        "confusion_matrix_labels": ["phishing(0)", "legitimate(1)"],
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist()
    }

    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("\nTraining completed.")
    print(classification_report(y_test, predictions, target_names=["Phishing", "Legitimate"], zero_division=0))
    print(f"Saved model: {MODEL_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")

if __name__ == "__main__":
    main()
