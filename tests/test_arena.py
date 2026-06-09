from phisharms import ArmsRace, RedTeam


def test_red_team_returns_report(trained_detector):
    report = RedTeam(attempts_per_email=8).attack(
        trained_detector, ["URGENT verify your account now http://bit.ly/x"]
    )
    assert report.n_attempted == 1
    assert 0.0 <= report.evasion_rate <= 1.0


def test_arena_runs_and_records_history(trained_detector, tiny_corpus):
    texts, labels = tiny_corpus
    phishing = [t for t, y in zip(texts, labels) if y == 1][:6]
    arena = ArmsRace(detector=trained_detector, red=RedTeam(attempts_per_email=6), generations=2)
    history = arena.run(phishing, texts, labels)

    assert len(history) == 2
    assert history[0].generation == 1
    # Clean accuracy should not collapse after hardening.
    assert history[-1].clean_accuracy > 0.6
