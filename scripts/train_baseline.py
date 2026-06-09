"""Train the Blue-team baseline detector and report held-out metrics."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phisharms.data import load_dataset  # noqa: E402
from phisharms.detector import PhishingDetector  # noqa: E402
from phisharms._console import enable_utf8  # noqa: E402

enable_utf8()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default=str(ROOT / "data" / "sample_emails.csv"))
    ap.add_argument("--out", default=str(ROOT / "models" / "detector.joblib"))
    ap.add_argument("--max-rows", type=int, default=None)
    args = ap.parse_args()

    df = load_dataset(args.data, max_rows=args.max_rows)
    X_tr, X_te, y_tr, y_te = train_test_split(
        df["text"].tolist(), df["label"].tolist(),
        test_size=0.25, stratify=df["label"], random_state=42,
    )

    print(f"Training on {len(X_tr)} emails…")
    det = PhishingDetector().train(X_tr, y_tr)
    metrics = det.score(X_te, y_te)

    print("\nHeld-out metrics:")
    for k, v in metrics.items():
        print(f"  {k:>10}: {v:.4f}")
    print("\nTop engineered-feature importances:")
    for name, imp in det.feature_importance()[:6]:
        print(f"  {name:>20}: {imp:.4f}")

    det.save(args.out)
    print(f"\nSaved detector → {args.out}")


if __name__ == "__main__":
    main()
