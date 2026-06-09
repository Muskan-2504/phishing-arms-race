from phisharms.features import FEATURE_NAMES, feature_vector


def test_feature_vector_matches_names():
    vec = feature_vector("Click here to verify http://x.io now!!!")
    assert len(vec) == len(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in vec)


def test_detector_learns_separation(trained_detector, tiny_corpus):
    texts, labels = tiny_corpus
    metrics = trained_detector.score(texts, labels)
    # On this trivially-separable toy set it should fit well.
    assert metrics["accuracy"] > 0.8


def test_harden_grows_corpus(trained_detector):
    before = len(trained_detector._texts)
    added = trained_detector.harden(["p@yp4l verify y0ur acc0unt n0w"])
    assert added == 1
    assert len(trained_detector._texts) == before + 1


def test_roundtrip_save_load(trained_detector, tmp_path):
    p = tmp_path / "det.joblib"
    trained_detector.save(p)
    from phisharms.detector import PhishingDetector

    reloaded = PhishingDetector.load(p)
    assert reloaded.predict(["urgent verify your bank account now"]).shape == (1,)
