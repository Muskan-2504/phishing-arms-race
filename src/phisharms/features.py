"""Adversarially-aware feature engineering.

Beyond the usual bag-of-words signal, real phishing leaves fingerprints in its
*structure*: obfuscated URLs, look-alike Unicode characters, invisible
zero-width padding, leetspeak. Several of the features below exist specifically
to catch the tricks the Red team (:mod:`phisharms.attacker`) uses to evade
detection — so as the attacker evolves, these signals become the Blue team's
counter-measure.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

# Ordered so the meta-feature matrix is stable across train / retrain / predict.
FEATURE_NAMES: list[str] = [
    "num_links",
    "capital_ratio",
    "spam_keyword_count",
    "urgency_score",
    "has_attachment_hint",
    "has_ip_url",
    "has_url_shortener",
    "num_exclamations",
    "homoglyph_score",
    "zero_width_count",
    "leetspeak_score",
    "text_length",
]

_SPAM_KEYWORDS = (
    "click", "verify", "urgent", "win", "offer", "login", "prize",
    "account", "password", "confirm", "suspend", "bank", "invoice",
)
_URGENCY_WORDS = (
    "urgent", "immediately", "now", "asap", "expires", "24 hours",
    "act now", "final notice", "last chance", "warning",
)
_SHORTENERS = ("bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly")

_URL_RE = re.compile(r"http[s]?://|hxxp", re.IGNORECASE)
_IP_URL_RE = re.compile(r"http[s]?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
_ZERO_WIDTH = "​‌‍﻿⁠"
_LEET_RE = re.compile(r"[a-z]+[0-9@$!][a-z0-9@$!]*", re.IGNORECASE)


def _is_homoglyph(ch: str) -> bool:
    """A non-ASCII letter that renders like a Latin one (Cyrillic/Greek look-alikes)."""
    if ch.isascii() or not ch.isalpha():
        return False
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return False
    # e.g. "CYRILLIC SMALL LETTER ES" looks like Latin 'c'.
    return any(script in name for script in ("CYRILLIC", "GREEK"))


def extract_features(text: str, sender: Optional[str] = None, urls: Optional[str] = None) -> dict[str, float]:
    """Return the engineered numeric features for one email as a name→value dict."""
    text = text or ""
    lower = text.lower()
    # `urls` column (when present in the dataset) gives extra link signal for free.
    link_corpus = f"{text} {urls or ''}"

    letters = [c for c in text if c.isalpha()]
    capital_ratio = (sum(1 for c in letters if c.isupper()) / len(letters)) if letters else 0.0

    return {
        "num_links": float(len(_URL_RE.findall(link_corpus))),
        "capital_ratio": round(capital_ratio, 4),
        "spam_keyword_count": float(sum(kw in lower for kw in _SPAM_KEYWORDS)),
        "urgency_score": float(sum(w in lower for w in _URGENCY_WORDS)),
        "has_attachment_hint": float(bool(re.search(r"\.(xls|pdf|doc|docx|zip|rar|exe)", lower))),
        "has_ip_url": float(bool(_IP_URL_RE.search(link_corpus))),
        "has_url_shortener": float(any(s in link_corpus.lower() for s in _SHORTENERS)),
        "num_exclamations": float(text.count("!")),
        "homoglyph_score": float(sum(_is_homoglyph(c) for c in text)),
        "zero_width_count": float(sum(text.count(z) for z in _ZERO_WIDTH)),
        "leetspeak_score": float(len(_LEET_RE.findall(text))),
        "text_length": float(len(text)),
    }


def feature_vector(text: str, sender: Optional[str] = None, urls: Optional[str] = None) -> list[float]:
    """Same as :func:`extract_features` but returns a list ordered by ``FEATURE_NAMES``."""
    feats = extract_features(text, sender, urls)
    return [feats[name] for name in FEATURE_NAMES]
