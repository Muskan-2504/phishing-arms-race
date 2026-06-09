from phisharms import mutations
from phisharms.features import extract_features


def test_every_operator_returns_nonempty(rng):
    text = "URGENT: verify your account password by clicking http://example.com now"
    for name, op in mutations.OPERATORS.items():
        out = op(text, rng)
        assert isinstance(out, str) and out, f"{name} produced empty output"


def test_homoglyph_introduces_non_ascii(rng):
    out = mutations.homoglyph("paypal account verification", rng, rate=1.0)
    assert any(not c.isascii() for c in out)
    # ...and our feature extractor notices it (the Blue counter-measure).
    assert extract_features(out)["homoglyph_score"] > 0


def test_zero_width_is_detectable(rng):
    out = mutations.zero_width("please verify your account", rng, rate=1.0)
    assert extract_features(out)["zero_width_count"] > 0


def test_apply_chain_composes(rng):
    out = mutations.apply_chain("urgent verify login", ["synonym_swap", "leetspeak"], rng)
    assert isinstance(out, str) and out
