import random

import pytest

from phisharms.detector import PhishingDetector


@pytest.fixture
def tiny_corpus():
    phishing = [
        "URGENT verify your account now click http://bit.ly/x to avoid suspension",
        "You won a prize! confirm your bank login immediately at http://1.2.3.4/win",
        "Security alert: password expires, login here http://tinyurl.com/p to reset",
        "Final notice: invoice.pdf attached, verify payment urgently now",
    ] * 6
    legit = [
        "Hi team, attaching the meeting notes from yesterday, talk soon",
        "Your order has shipped and will arrive on Tuesday, thanks for shopping",
        "Reminder: the quarterly review is scheduled for next Friday afternoon",
        "Lunch plans? I was thinking the new place downtown around noon",
    ] * 6
    texts = phishing + legit
    labels = [1] * len(phishing) + [0] * len(legit)
    return texts, labels


@pytest.fixture
def trained_detector(tiny_corpus):
    texts, labels = tiny_corpus
    return PhishingDetector(n_estimators=40, max_features=300).train(texts, labels)


@pytest.fixture
def rng():
    return random.Random(0)
