"""Dataset loading helpers.

The repository ships with a small balanced sample (``data/sample_emails.csv``)
so everything runs out of the box. To reproduce the full-scale results, drop the
original Kaggle CSVs into ``data/raw/`` and point ``load_dataset`` at them — see
the README's "Data" section.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

# Candidate column names across the various public phishing datasets.
_TEXT_COLS = ("text", "body", "text_combined", "email", "message")
_LABEL_COLS = ("label", "is_phishing", "class", "target")


def _pick(columns, candidates) -> str | None:
    lower = {c.lower(): c for c in columns}
    for cand in candidates:
        if cand in lower:
            return lower[cand]
    return None


def load_dataset(path: str | Path, max_rows: int | None = None, seed: int = 42) -> pd.DataFrame:
    """Load any of the supported phishing CSVs into a tidy ``text`` / ``label`` frame."""
    df = pd.read_csv(path, encoding="latin1", on_bad_lines="skip", low_memory=False)
    text_col = _pick(df.columns, _TEXT_COLS)
    label_col = _pick(df.columns, _LABEL_COLS)
    if text_col is None or label_col is None:
        raise ValueError(f"Could not find text/label columns in {list(df.columns)}")

    out = pd.DataFrame({
        "text": df[text_col].astype(str),
        "label": pd.to_numeric(df[label_col], errors="coerce"),
    }).dropna()
    out["label"] = out["label"].astype(int)
    out = out[out["text"].str.strip().str.len() > 0]

    if max_rows and len(out) > max_rows:
        # Stratified-ish sample: keep class balance.
        out = out.groupby("label", group_keys=False).apply(
            lambda g: g.sample(min(len(g), max_rows // 2), random_state=seed)
        )
    return out.sample(frac=1, random_state=seed).reset_index(drop=True)


def phishing_subset(df: pd.DataFrame) -> list[str]:
    """Return just the phishing texts (label == 1) — the Red team's ammunition."""
    return df.loc[df["label"] == 1, "text"].tolist()
