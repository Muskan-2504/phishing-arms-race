"""The arena: the generational co-evolution loop.

Each generation:

1. **Red attacks** the current detector on a held-out set of phishing emails and
   records every evasion it finds (the *pre-hardening* evasion rate).
2. **Blue hardens** by folding those evasions into its training corpus and
   refitting.
3. We re-measure the evasion rate and the clean-set accuracy to confirm the
   detector got tougher *without* forgetting how to classify normal mail.

Over generations the evasion rate should fall and the operator-win distribution
should shift — a measurable arms race.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Sequence

from phisharms.attacker import RedTeam
from phisharms.detector import PhishingDetector

log = logging.getLogger(__name__)


@dataclass
class GenerationStats:
    generation: int
    evasion_rate_before: float
    evasion_rate_after: float
    evasions_found: int
    clean_accuracy: float
    clean_recall: float
    operator_wins: dict[str, int] = field(default_factory=dict)
    example_evasions: list[dict] = field(default_factory=list)


@dataclass
class ArmsRace:
    detector: PhishingDetector
    red: RedTeam
    generations: int = 5

    def run(
        self,
        attack_pool: Sequence[str],
        clean_texts: Sequence[str],
        clean_labels: Sequence[int],
    ) -> list[GenerationStats]:
        """Run the co-evolution loop and return per-generation statistics."""
        history: list[GenerationStats] = []

        for gen in range(1, self.generations + 1):
            log.info("─── Generation %d/%d ───", gen, self.generations)

            # 1. Red attacks the current detector.
            report = self.red.attack(self.detector, attack_pool)
            rate_before = report.evasion_rate

            # 2. Blue hardens on the evasions Red just found.
            self.detector.harden([e.mutated for e in report.evasions])

            # 3. Re-measure: how many of the *same* attacks still work, and is the
            #    detector still healthy on clean mail?
            after = self.red.attack(self.detector, attack_pool)
            clean = self.detector.score(clean_texts, clean_labels)

            history.append(GenerationStats(
                generation=gen,
                evasion_rate_before=round(rate_before, 4),
                evasion_rate_after=round(after.evasion_rate, 4),
                evasions_found=len(report.evasions),
                clean_accuracy=round(clean["accuracy"], 4),
                clean_recall=round(clean["recall"], 4),
                operator_wins=dict(report.operator_wins),
                example_evasions=[
                    {"original": e.original[:160], "mutated": e.mutated[:160],
                     "ops": e.ops, "orig_prob": round(e.orig_prob, 3), "new_prob": round(e.new_prob, 3)}
                    for e in report.evasions[:3]
                ],
            ))
            log.info("Gen %d: evasion %.1f%% → %.1f%% after hardening | clean acc %.3f",
                     gen, 100 * rate_before, 100 * after.evasion_rate, clean["accuracy"])

        return history

    @staticmethod
    def save_history(history: list[GenerationStats], path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([asdict(h) for h in history], indent=2), encoding="utf-8")
