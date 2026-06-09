# Architecture

PhishArms is organised as a small, testable Python package (`src/phisharms/`)
with thin entry points (`scripts/`, `dashboard/`) on top.

```
                    ┌─────────────────────────────────────────────┐
                    │                  arena.py                    │
                    │            (co-evolution loop)               │
                    └───────────────┬──────────────┬──────────────┘
                                    │              │
                  attacks (probs)   │              │  harden(evasions)
                                    ▼              ▼
        ┌───────────────────────────────┐   ┌───────────────────────────────┐
        │          attacker.py          │   │          detector.py          │
        │   Red team — black-box search │   │   Blue team — TF-IDF + RF     │
        │   over mutation chains        │   │   + engineered features       │
        └───────────────┬───────────────┘   └───────────────┬───────────────┘
                        │                                    │
                        ▼                                    ▼
              ┌───────────────────┐                ┌───────────────────┐
              │   mutations.py    │                │    features.py    │
              │  6 evasion ops    │  ⟷ adversarial │  12 signals, some │
              │  (leet, homoglyph,│     symmetry   │  built to catch   │
              │   zero-width, …)  │                │  those very ops   │
              └───────────────────┘                └───────────────────┘
```

## The adversarial symmetry

The design's core idea: several Blue-team **features** exist specifically to
detect Red-team **mutations**.

| Red mutation (`mutations.py`) | Blue counter-feature (`features.py`) |
| ----------------------------- | ------------------------------------ |
| `homoglyph` (Cyrillic/Greek)  | `homoglyph_score`                    |
| `zero_width` injection        | `zero_width_count`                   |
| `leetspeak` (p@yp4l)          | `leetspeak_score`                    |
| `url_obfuscate` (hxxp, [.])   | `num_links`, `has_ip_url`            |
| `benign_padding`              | `text_length`, `capital_ratio`       |

So when Red leans on a tactic, the corresponding feature lights up, and once
those evasions are folded back in via `harden()`, Blue learns to weight it.

## The co-evolution loop (`arena.py`)

For each generation:

1. **Red attacks** — for every phishing email in the attack pool, the attacker
   tries up to *N* random mutation chains and keeps the one that most lowers the
   detector's phishing probability below its threshold (black-box; it only sees
   output probabilities).
2. **Blue hardens** — every discovered evasion is appended to the training
   corpus with label = phishing, and the model refits.
3. **Re-measure** — we recompute the evasion rate (did hardening close the hole?)
   and the clean-set accuracy (did we avoid catastrophic forgetting?).

History is serialised to `results/history.json` and rendered to charts by
`viz.py`.

## Why this layout

- **`src/` layout** keeps the importable package isolated from scripts/tests and
  makes packaging unambiguous.
- **Dataclasses** (`PhishingDetector`, `RedTeam`, `ArmsRace`, `Evasion`,
  `GenerationStats`) give typed, inspectable state with no framework lock-in.
- **Operator registry** (`mutations.OPERATORS`) lets the attacker and the arena
  treat strategies as data — new evasions are one function + one dict entry.
- **Deterministic seeds** everywhere (`random.Random(seed)`, `random_state=42`)
  so every run in the README is reproducible.
