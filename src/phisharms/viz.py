"""Plotting helpers — turn arms-race history into the charts used in the README."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import matplotlib

matplotlib.use("Agg")  # headless / CI-safe
import matplotlib.pyplot as plt  # noqa: E402


def plot_evasion_curve(history: Sequence, out_path: str | Path) -> Path:
    """Evasion rate before/after hardening, per generation."""
    gens = [h.generation for h in history]
    before = [100 * h.evasion_rate_before for h in history]
    after = [100 * h.evasion_rate_after for h in history]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.plot(gens, before, "o-", color="#d64550", label="Evasion rate (Red attacks)")
    ax.plot(gens, after, "s--", color="#2a9d8f", label="After Blue hardens")
    ax.set_xlabel("Generation")
    ax.set_ylabel("Evasion rate (%)")
    ax.set_title("Phishing Arms Race — evasion rate over generations")
    ax.set_xticks(gens)
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    return out_path


def plot_operator_phylogeny(history: Sequence, out_path: str | Path) -> Path:
    """Stacked bars showing which mutation operators won each generation."""
    op_names = sorted({op for h in history for op in h.operator_wins})
    gens = [h.generation for h in history]
    bottoms = [0.0] * len(gens)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    cmap = plt.get_cmap("tab10")
    for i, op in enumerate(op_names):
        vals = [h.operator_wins.get(op, 0) for h in history]
        ax.bar(gens, vals, bottom=bottoms, label=op, color=cmap(i % 10))
        bottoms = [b + v for b, v in zip(bottoms, vals)]
    ax.set_xlabel("Generation")
    ax.set_ylabel("Successful evasions using operator")
    ax.set_title("Mutation-strategy phylogeny — which attacks survive selection")
    ax.set_xticks(gens)
    ax.legend(fontsize=8, ncol=2)
    fig.tight_layout()
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    return out_path
