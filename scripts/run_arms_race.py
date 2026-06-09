"""Run the full self-evolving arms race and emit results + charts.

This is the project's headline entry point:

    python scripts/run_arms_race.py --generations 5

It trains a fresh Blue detector, unleashes the Red attacker, and runs the
co-evolution loop — writing ``results/history.json`` plus the evasion-curve and
operator-phylogeny charts used in the README.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phisharms import ArmsRace, PhishingDetector, RedTeam  # noqa: E402
from phisharms.data import load_dataset, phishing_subset  # noqa: E402
from phisharms import viz  # noqa: E402
from phisharms._console import enable_utf8  # noqa: E402

enable_utf8()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default=str(ROOT / "data" / "sample_emails.csv"))
    ap.add_argument("--generations", type=int, default=5)
    ap.add_argument("--attack-pool", type=int, default=60, help="# phishing emails Red attacks each gen")
    ap.add_argument("--attempts", type=int, default=12, help="Mutation attempts per email")
    ap.add_argument("--results", default=str(ROOT / "results"))
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    df = load_dataset(args.data)
    train_df, clean_df = train_test_split(df, test_size=0.25, stratify=df["label"], random_state=42)

    print(f"Training Blue detector on {len(train_df)} emails…")
    detector = PhishingDetector().train(train_df["text"].tolist(), train_df["label"].tolist())

    attack_pool = phishing_subset(train_df)[: args.attack_pool]
    red = RedTeam(attempts_per_email=args.attempts)
    arena = ArmsRace(detector=detector, red=red, generations=args.generations)

    print(f"\nRunning arms race: {args.generations} generations, {len(attack_pool)} attack emails/gen\n")
    history = arena.run(attack_pool, clean_df["text"].tolist(), clean_df["label"].tolist())

    results = Path(args.results)
    arena.save_history(history, results / "history.json")
    viz.plot_evasion_curve(history, results / "evasion_curve.png")
    viz.plot_operator_phylogeny(history, results / "operator_phylogeny.png")
    detector.save(ROOT / "models" / "detector_hardened.joblib")

    g0, gN = history[0], history[-1]
    print("\n══════════════ ARMS RACE SUMMARY ══════════════")
    print(f"  Gen 1 evasion rate : {g0.evasion_rate_before:.1%}")
    print(f"  Gen {gN.generation} evasion rate : {gN.evasion_rate_before:.1%}")
    drop = g0.evasion_rate_before - gN.evasion_rate_before
    print(f"  Robustness gain    : {drop:.1%} fewer successful evasions")
    print(f"  Clean accuracy     : {g0.clean_accuracy:.3f} → {gN.clean_accuracy:.3f} (no catastrophic forgetting)")
    print(f"\n  Results → {results}")


if __name__ == "__main__":
    main()
