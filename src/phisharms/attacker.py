"""The Red team: a black-box evasion attacker.

Given a batch of phishing emails and a (frozen) detector, the attacker searches
for mutation chains that push the detector's phishing probability below its
decision threshold while keeping the message human-readable. It only ever reads
the detector's *output probabilities* — never its internals — so this is a
realistic black-box attack.
"""

from __future__ import annotations

import logging
import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Sequence

from phisharms.mutations import OPERATORS, apply_chain

log = logging.getLogger(__name__)


@dataclass
class Evasion:
    """A successful attack: the mutated text and the operator chain that produced it."""

    original: str
    mutated: str
    ops: list[str]
    orig_prob: float
    new_prob: float


@dataclass
class AttackReport:
    evasions: list[Evasion] = field(default_factory=list)
    n_attempted: int = 0
    operator_wins: Counter = field(default_factory=Counter)

    @property
    def evasion_rate(self) -> float:
        return len(self.evasions) / self.n_attempted if self.n_attempted else 0.0


@dataclass
class RedTeam:
    """Searches for detector-evading mutations of phishing emails."""

    attempts_per_email: int = 12
    max_ops: int = 3
    seed: int = 7

    def attack(self, detector, phishing_texts: Sequence[str]) -> AttackReport:
        """Try to evade ``detector`` for each phishing email in ``phishing_texts``."""
        rng = random.Random(self.seed)
        op_names = list(OPERATORS)
        report = AttackReport(n_attempted=len(phishing_texts))

        orig_probs = detector.predict_proba(list(phishing_texts))

        for text, orig_prob in zip(phishing_texts, orig_probs):
            best: Evasion | None = None
            for _ in range(self.attempts_per_email):
                k = rng.randint(1, self.max_ops)
                ops = rng.sample(op_names, k=k)
                mutated = apply_chain(text, ops, rng)
                new_prob = float(detector.predict_proba([mutated])[0])
                # Evasion = pushed below threshold; keep the strongest (lowest prob).
                if new_prob < detector.threshold and (best is None or new_prob < best.new_prob):
                    best = Evasion(text, mutated, ops, float(orig_prob), new_prob)
            if best is not None:
                report.evasions.append(best)
                report.operator_wins.update(best.ops)

        log.info("Red team: %d/%d emails evaded (%.1f%%)",
                 len(report.evasions), report.n_attempted, 100 * report.evasion_rate)
        return report
