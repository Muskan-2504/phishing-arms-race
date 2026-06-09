"""Build the small balanced sample shipped with the repo.

Reads one or more of the large public phishing CSVs and writes a compact,
class-balanced ``data/sample_emails.csv`` (kept under version control) so the
project runs without the multi-hundred-MB raw datasets.

Usage:
    python scripts/build_sample.py --inputs data/raw/CEAS_08.csv data/raw/phishing_email.csv --n 3000
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phisharms.data import load_dataset  # noqa: E402
from phisharms._console import enable_utf8  # noqa: E402

enable_utf8()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inputs", nargs="+", required=True, help="Raw CSV paths")
    ap.add_argument("--n", type=int, default=3000, help="Total rows in the sample")
    ap.add_argument("--out", default=str(ROOT / "data" / "sample_emails.csv"))
    args = ap.parse_args()

    frames = []
    per_file = max(args.n // len(args.inputs), 2)
    for path in args.inputs:
        df = load_dataset(path, max_rows=per_file)
        frames.append(df)
        print(f"  loaded {len(df):>6} rows from {path}")

    combined = pd.concat(frames, ignore_index=True).drop_duplicates(subset="text")
    # Trim text so the sample CSV stays small and git-friendly.
    combined["text"] = combined["text"].str.slice(0, 2000)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(out, index=False)
    counts = combined["label"].value_counts().to_dict()
    print(f"\nWrote {len(combined)} rows → {out}  (labels: {counts})")


if __name__ == "__main__":
    main()
