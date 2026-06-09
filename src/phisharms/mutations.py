"""The Red team's arsenal: semantics-preserving evasion mutations.

Each operator takes a string and a seeded :class:`random.Random` and returns a
perturbed string that a *human* still reads as the same phishing message, but
that shifts the email's feature representation enough to (hopefully) fool the
detector. Operators are intentionally small and composable — the attacker
chains several together to search the evasion space.

All operators are registered in :data:`OPERATORS` so the attacker can sample
them by name and the arena can track which strategies survive over generations.
"""

from __future__ import annotations

import random
import re
from typing import Callable

# --- character-level confusables --------------------------------------------
_LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"}
# Latin → visually-identical Cyrillic/Greek code points.
_HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
_ZERO_WIDTH = "​"  # zero-width space

# --- token-level paraphrase -------------------------------------------------
_SYNONYMS = {
    "urgent": "time-sensitive", "verify": "confirm", "account": "profile",
    "click": "tap", "password": "credentials", "suspended": "limited",
    "immediately": "right away", "login": "sign in", "bank": "financial institution",
}


def leetspeak(text: str, rng: random.Random, rate: float = 0.4) -> str:
    """Replace some letters with look-alike digits/symbols (paypal → p@yp4l)."""
    out = []
    for ch in text:
        low = ch.lower()
        if low in _LEET and rng.random() < rate:
            out.append(_LEET[low])
        else:
            out.append(ch)
    return "".join(out)


def homoglyph(text: str, rng: random.Random, rate: float = 0.3) -> str:
    """Swap Latin letters for identical-looking Cyrillic/Greek characters."""
    out = []
    for ch in text:
        low = ch.lower()
        if low in _HOMOGLYPHS and rng.random() < rate:
            sub = _HOMOGLYPHS[low]
            out.append(sub.upper() if ch.isupper() else sub)
        else:
            out.append(ch)
    return "".join(out)


def zero_width(text: str, rng: random.Random, rate: float = 0.5) -> str:
    """Inject invisible zero-width spaces inside spam keywords to break tokens."""
    targets = ("verify", "account", "password", "click", "login", "urgent", "bank")
    for kw in targets:
        if kw in text.lower() and rng.random() < rate:
            broken = _ZERO_WIDTH.join(kw)
            text = re.sub(re.escape(kw), broken, text, flags=re.IGNORECASE)
    return text


def synonym_swap(text: str, rng: random.Random, rate: float = 0.6) -> str:
    """Replace trigger words with benign-sounding synonyms."""
    def repl(m: re.Match) -> str:
        word = m.group(0)
        key = word.lower()
        if key in _SYNONYMS and rng.random() < rate:
            return _SYNONYMS[key]
        return word

    pattern = re.compile("|".join(rf"\b{re.escape(w)}\b" for w in _SYNONYMS), re.IGNORECASE)
    return pattern.sub(repl, text)


def url_obfuscate(text: str, rng: random.Random, **_: float) -> str:
    """Disguise URLs the way real phishers do (http → hxxp, dotted scheme)."""
    text = re.sub(r"https?://", lambda m: rng.choice(["hxxp://", "hxxps://", "h_t_t_p://"]), text)
    return text.replace(".", "[.]") if rng.random() < 0.3 else text


def benign_padding(text: str, rng: random.Random, **_: float) -> str:
    """Dilute the phishing signal with innocuous filler sentences (signal-flooding)."""
    fillers = [
        "Thank you for being a valued customer.",
        "We appreciate your continued trust in our services.",
        "This message was sent in accordance with our policy.",
        "Please do not reply directly to this automated notice.",
    ]
    pad = " ".join(rng.sample(fillers, k=rng.randint(1, len(fillers))))
    return f"{pad} {text} {pad}"


# Registry — name → operator. The attacker samples from these by name.
OPERATORS: dict[str, Callable[..., str]] = {
    "leetspeak": leetspeak,
    "homoglyph": homoglyph,
    "zero_width": zero_width,
    "synonym_swap": synonym_swap,
    "url_obfuscate": url_obfuscate,
    "benign_padding": benign_padding,
}


def apply_chain(text: str, ops: list[str], rng: random.Random) -> str:
    """Apply a sequence of named operators in order."""
    for name in ops:
        text = OPERATORS[name](text, rng)
    return text
