"""PhishArms control room — a Streamlit dashboard.

Three tabs:
  1. Arms Race    — visualise the co-evolution results (evasion curve, phylogeny).
  2. Live Probe   — paste an email and watch the detector + Red team react in real time.
  3. Gmail Scan   — scan a live inbox over IMAP (credentials via .env, never hardcoded).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phisharms.detector import PhishingDetector  # noqa: E402
from phisharms.attacker import RedTeam  # noqa: E402
from phisharms.features import extract_features  # noqa: E402

st.set_page_config(page_title="PhishArms — Arms Race Control Room", page_icon="🧬", layout="wide")


@st.cache_resource
def load_detector() -> PhishingDetector | None:
    for name in ("detector_hardened.joblib", "detector.joblib"):
        p = ROOT / "models" / name
        if p.exists():
            return PhishingDetector.load(p)
    return None


st.title("🧬 PhishArms — Self-Evolving Phishing Defense")
st.caption("Red attacker vs Blue detector, co-evolving over generations.")

detector = load_detector()
if detector is None:
    st.warning("No trained model found. Run `python scripts/train_baseline.py` first.")

tab_race, tab_probe, tab_gmail = st.tabs(["⚔️ Arms Race", "🔬 Live Probe", "📬 Gmail Scan"])

# ───────────────────────────────────────── Arms Race
with tab_race:
    hist_path = ROOT / "results" / "history.json"
    if not hist_path.exists():
        st.info("Run `python scripts/run_arms_race.py` to generate arms-race results.")
    else:
        history = json.loads(hist_path.read_text(encoding="utf-8"))
        c1, c2, c3 = st.columns(3)
        g0, gN = history[0], history[-1]
        c1.metric("Gen-1 evasion rate", f"{g0['evasion_rate_before']:.0%}")
        c2.metric("Final evasion rate", f"{gN['evasion_rate_before']:.0%}",
                  delta=f"{(gN['evasion_rate_before'] - g0['evasion_rate_before']):.0%}", delta_color="inverse")
        c3.metric("Clean accuracy", f"{gN['clean_accuracy']:.1%}")

        for img in ("evasion_curve.png", "operator_phylogeny.png"):
            p = ROOT / "results" / img
            if p.exists():
                st.image(str(p), use_container_width=True)

        st.subheader("Example evasions Red discovered")
        rows = [{"Gen": h["generation"], **e} for h in history for e in h["example_evasions"]]
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)

# ───────────────────────────────────────── Live Probe
with tab_probe:
    st.write("Paste an email body. The detector scores it; the Red team then tries to evade.")
    sample = "URGENT: your account will be suspended. Verify now: http://bit.ly/secure-login"
    text = st.text_area("Email body", value=sample, height=140)
    if st.button("Analyse", type="primary") and detector and text.strip():
        prob = float(detector.predict_proba([text])[0])
        verdict = "🚨 Phishing" if prob >= detector.threshold else "✅ Legitimate"
        st.metric("Detector verdict", verdict, delta=f"{prob:.1%} phishing probability")

        with st.expander("Engineered features"):
            st.json(extract_features(text))

        st.subheader("🔴 Red team evasion attempt")
        report = RedTeam(attempts_per_email=20).attack(detector, [text])
        if report.evasions:
            ev = report.evasions[0]
            st.error(f"Evaded! prob {ev.orig_prob:.1%} → {ev.new_prob:.1%} via {', '.join(ev.ops)}")
            st.code(ev.mutated)
        else:
            st.success("Detector held — Red team could not evade it. 🛡️")

# ───────────────────────────────────────── Gmail Scan
with tab_gmail:
    st.write("Scan a live Gmail inbox over IMAP. Credentials are read from `.env` — never hardcoded.")
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env")
    except ImportError:
        pass

    addr = os.getenv("GMAIL_ADDRESS")
    pw = os.getenv("GMAIL_APP_PASSWORD")
    if not addr or not pw:
        st.info("Set GMAIL_ADDRESS and GMAIL_APP_PASSWORD in a `.env` file (see `.env.example`).")
    elif st.button("🔄 Scan inbox") and detector:
        from gmail_scan import fetch_latest_emails  # local helper

        with st.spinner("Connecting to Gmail…"):
            emails = fetch_latest_emails(addr, pw, os.getenv("IMAP_SERVER", "imap.gmail.com"), n=30)
        if isinstance(emails, str):
            st.error(emails)
        else:
            probs = detector.predict_proba(emails)
            df = pd.DataFrame({"Email (truncated)": [e[:120] for e in emails],
                               "Phishing %": (probs * 100).round(1)})
            df["Verdict"] = ["🚨 Phishing" if p >= detector.threshold else "✅ Legit" for p in probs]
            st.success(f"Scanned {len(df)} emails")
            st.dataframe(df, use_container_width=True)
            st.download_button("⬇️ Download CSV", df.to_csv(index=False), "scan_results.csv", "text/csv")
