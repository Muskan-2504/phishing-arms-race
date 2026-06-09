"""PhishArms — a self-evolving phishing detection arms race.

Two agents co-evolve over generations:

* :mod:`phisharms.detector`  — the Blue team classifier that learns to detect phishing.
* :mod:`phisharms.attacker`  — the Red team that mutates phishing emails to evade Blue.

The :mod:`phisharms.arena` ties them together into a generational loop in which every
evasion Red discovers is folded back into Blue's training set, hardening it against
attacks it has never seen.
"""

__version__ = "1.0.0"

from phisharms.detector import PhishingDetector
from phisharms.attacker import RedTeam
from phisharms.arena import ArmsRace

__all__ = ["PhishingDetector", "RedTeam", "ArmsRace", "__version__"]
