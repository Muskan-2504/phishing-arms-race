"""The Blue team: a phishing detector that can be hardened in place.

Combines TF-IDF over the raw text with the adversarially-aware engineered
features from :mod:`phisharms.features`. The key method for the arms race is
:meth:`PhishingDetector.harden`, which folds freshly-discovered evasions back
into the training corpus and refits — the model literally learns from the
attacks it just failed to catch.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

from phisharms.features import FEATURE_NAMES, feature_vector

log = logging.getLogger(__name__)


@dataclass
class PhishingDetector:
    """A TF-IDF + engineered-features Random Forest phishing classifier.

    The training corpus is retained in-memory so the detector can be *hardened*
    incrementally during the arms race without re-reading the dataset.
    """

    max_features: int = 5000
    n_estimators: int = 200
    random_state: int = 42
    threshold: float = 0.5

    vectorizer: TfidfVectorizer = field(init=False, default=None)
    model: RandomForestClassifier = field(init=False, default=None)
    _texts: list[str] = field(init=False, default_factory=list)
    _labels: list[int] = field(init=False, default_factory=list)

    # ------------------------------------------------------------------ build
    def _matrix(self, texts: Sequence[str], fit: bool = False) -> csr_matrix:
        if fit:
            tfidf = self.vectorizer.fit_transform(texts)
        else:
            tfidf = self.vectorizer.transform(texts)
        meta = np.array([feature_vector(t) for t in texts], dtype=float)
        return hstack([tfidf, csr_matrix(meta)]).tocsr()

    def train(self, texts: Sequence[str], labels: Sequence[int]) -> "PhishingDetector":
        """Fit the vectorizer and model from scratch on ``texts`` / ``labels``."""
        self._texts = list(texts)
        self._labels = [int(x) for x in labels]
        self.vectorizer = TfidfVectorizer(stop_words="english", max_features=self.max_features)
        X = self._matrix(self._texts, fit=True)
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            class_weight="balanced",
            n_jobs=-1,
        )
        self.model.fit(X, self._labels)
        log.info("Trained on %d emails (%d features)", len(self._texts), X.shape[1])
        return self

    def harden(self, evasions: Sequence[str], labels: Optional[Sequence[int]] = None) -> int:
        """Add discovered evasions (phishing by default) to the corpus and refit.

        Returns the number of samples added. This is the Blue team's move in the
        arms race: every attack that slipped through becomes a training example.
        """
        if not evasions:
            return 0
        labels = [1] * len(evasions) if labels is None else [int(x) for x in labels]
        self._texts.extend(evasions)
        self._labels.extend(labels)
        # Refit on the augmented corpus (vocabulary may grow with new obfuscations).
        X = self._matrix(self._texts, fit=True)
        self.model.fit(X, self._labels)
        log.info("Hardened with %d evasions → corpus now %d emails", len(evasions), len(self._texts))
        return len(evasions)

    # --------------------------------------------------------------- predict
    def predict_proba(self, texts: Sequence[str]) -> np.ndarray:
        """Probability that each email is phishing (class 1)."""
        X = self._matrix(list(texts), fit=False)
        return self.model.predict_proba(X)[:, 1]

    def predict(self, texts: Sequence[str]) -> np.ndarray:
        return (self.predict_proba(texts) >= self.threshold).astype(int)

    def score(self, texts: Sequence[str], labels: Sequence[int]) -> dict[str, float]:
        """Accuracy / precision / recall / f1 on a labelled set."""
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support

        preds = self.predict(texts)
        p, r, f1, _ = precision_recall_fscore_support(labels, preds, average="binary", zero_division=0)
        return {
            "accuracy": float(accuracy_score(labels, preds)),
            "precision": float(p),
            "recall": float(r),
            "f1": float(f1),
        }

    def feature_importance(self) -> list[tuple[str, float]]:
        """Importance of the engineered (non-TF-IDF) features, most important first."""
        importances = self.model.feature_importances_[-len(FEATURE_NAMES):]
        ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda kv: kv[1], reverse=True)
        return [(name, float(v)) for name, v in ranked]

    # ------------------------------------------------------------------- io
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> "PhishingDetector":
        return joblib.load(path)
