"""PhishArms — a clean, single-page dashboard built for non-technical viewers.

Card-based, guided flow: paste an email → get a clear verdict with plain-language
reasons → watch the Red-team attacker try (and usually fail) to fool the hardened
detector → see how the model improved over the arms race. No jargon, no clutter.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # for gmail_scan

from phisharms.detector import PhishingDetector  # noqa: E402
from phisharms.features import _SPAM_KEYWORDS, _URGENCY_WORDS, extract_features  # noqa: E402

GITHUB_URL = "https://github.com/Muskan-2504/phishing-arms-race"
RED, GREEN, AMBER, INK = "#D64550", "#2A9D8F", "#F79009", "#111827"

st.set_page_config(page_title="PhishArms", page_icon="🛡️", layout="wide")

st.markdown(
    f"""
    <style>
      #MainMenu, header, footer {{visibility: hidden;}}
      .block-container {{padding-top: 1.6rem; max-width: 1080px;}}
      h1, h2, h3 {{color: {INK};}}
      /* native bordered containers -> soft cards */
      div[data-testid="stVerticalBlockBorderWrapper"] {{
        border-radius: 14px !important; border-color:#E6E9EF !important;
        box-shadow: 0 1px 3px rgba(16,24,40,.04); padding:.35rem;}}
      .brand {{font-size: 1.9rem; font-weight: 800; letter-spacing:-.02em; margin:0;}}
      .tagline {{color:#6B7280; margin:.15rem 0 0 0; font-size:1.02rem;}}
      .step {{font-size:.78rem; font-weight:700; letter-spacing:.06em; color:#9098A4; text-transform:uppercase;}}
      .verdict {{padding:1.1rem 1.3rem; border-radius:12px; font-weight:800; font-size:1.45rem; color:#fff;}}
      .pill {{display:inline-block; padding:.18rem .7rem; border-radius:999px; font-size:.8rem; font-weight:700;}}
      .meter {{height:18px; width:100%; background:#EEF1F6; border-radius:999px; overflow:hidden; margin-top:.3rem;}}
      .meter-fill {{height:100%; border-radius:999px;}}
      .reason {{padding:.5rem 0; border-bottom:1px solid #F0F2F5;}}
      .reason b {{color:{INK};}} .reason span {{color:#6B7280; font-size:.9rem;}}
      .foot {{color:#9098A4; font-size:.85rem; text-align:center; margin-top:1.4rem;}}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def load_detector():
    for name in ("detector_hardened.joblib", "detector.joblib"):
        p = ROOT / "models" / name
        if p.exists():
            return PhishingDetector.load(p), datetime.fromtimestamp(p.stat().st_mtime)
    return None, None


@st.cache_data
def load_history():
    p = ROOT / "results" / "history.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


PHISHING_SAMPLE = (
    "URGENT: Your account has been temporarily suspended due to unusual activity. "
    "You must verify your identity immediately to avoid permanent closure. "
    "Confirm your login details here: http://bit.ly/secure-verify-now"
)
SAFE_SAMPLE = (
    "Hi team, attaching the notes from this morning's planning meeting. "
    "Let's regroup on Thursday to finalise the timeline. Thanks, Priya"
)


def matched(words, text: str) -> list[str]:
    low = text.lower()
    return [w for w in words if w in low]


def reasons_for(text: str) -> list[tuple[str, str]]:
    f = extract_features(text)
    out: list[tuple[str, str]] = []
    if f["has_url_shortener"]:
        out.append(("Shortened link (bit.ly, tinyurl…)", "hides the real destination"))
    if f["has_ip_url"]:
        out.append(("Links to a raw IP address", "real companies use named domains"))
    if f["num_links"]:
        out.append((f"Contains {int(f['num_links'])} link(s)", "phishing wants you to click"))
    urg = matched(_URGENCY_WORDS, text)
    if urg:
        out.append((f"Urgency language: “{'”, “'.join(urg[:3])}”", "rushes you into a mistake"))
    spam = matched(_SPAM_KEYWORDS, text)
    if len(spam) >= 2:
        out.append((f"Credential wording: “{'”, “'.join(spam[:3])}”", "asks you to confirm account details"))
    if f["leetspeak_score"] >= 2:
        out.append(("Letters disguised as symbols", "e.g. p@yp4l — dodges filters"))
    if f["homoglyph_score"]:
        out.append(("Look-alike foreign characters", "Cyrillic/Greek letters imitating English"))
    if f["zero_width_count"]:
        out.append(("Hidden invisible characters", "inserted to break up flagged words"))
    if f["capital_ratio"] > 0.30:
        out.append(("Excessive capital letters", "shouting is common in scams"))
    if f["has_attachment_hint"]:
        out.append(("Mentions an attachment", "a frequent malware vector"))
    return out


def risk_band(prob: float) -> tuple[str, str]:
    if prob >= 0.70:
        return "High risk", RED
    if prob >= 0.40:
        return "Medium risk", AMBER
    return "Low risk", GREEN


detector, _ = load_detector()
history = load_history()

# ── header ─────────────────────────────────────────────────────────────────
hl, hr = st.columns([3, 1])
with hl:
    st.markdown('<p class="brand">🛡️ PhishArms</p>', unsafe_allow_html=True)
    st.markdown('<p class="tagline">A phishing detector that trains against an attacker trying to '
                'beat it — and gets stronger every round.</p>', unsafe_allow_html=True)
with hr:
    st.write("")
    st.markdown(f"<div style='text-align:right'><a href='{GITHUB_URL}'>View source on GitHub ↗</a></div>",
                unsafe_allow_html=True)

if detector is None:
    st.warning("No trained model found. Run `python scripts/train_baseline.py` first, then reload.")
    st.stop()

st.write("")

# ── step 1: input · track record ─────────────────────────────────────────────
col_in, col_eval = st.columns([1.3, 1], gap="large")

with col_in:
    with st.container(border=True):
        st.markdown('<span class="step">Step 1 — try it</span>', unsafe_allow_html=True)
        st.markdown("#### Check an email")
        if "email_text" not in st.session_state:
            st.session_state.email_text = PHISHING_SAMPLE
        b1, b2, b3 = st.columns(3)
        if b1.button("Phishing example", use_container_width=True):
            st.session_state.email_text = PHISHING_SAMPLE
        if b2.button("Safe example", use_container_width=True):
            st.session_state.email_text = SAFE_SAMPLE
        if b3.button("Clear", use_container_width=True):
            st.session_state.email_text = ""
        st.text_area("Email text", key="email_text", height=180, label_visibility="collapsed",
                     placeholder="Paste the body of an email here…")
        analyse = st.button("🔍 Analyse email", type="primary", use_container_width=True)

with col_eval:
    with st.container(border=True):
        st.markdown('<span class="step">The proof it learns</span>', unsafe_allow_html=True)
        st.markdown("#### Detector track record")
        if history:
            c1, c2 = st.columns(2)
            c1.metric("Beat it at first", f"{history[0]['evasion_rate_before']:.0%}")
            c2.metric("After training", f"{history[-1]['evasion_rate_before']:.0%}",
                      delta=f"{(history[-1]['evasion_rate_before'] - history[0]['evasion_rate_before']):.0%}",
                      delta_color="inverse")
            df = pd.DataFrame({"Attack success %": [h["evasion_rate_before"] * 100 for h in history]},
                              index=[f"Round {h['generation']}" for h in history])
            st.caption("Share of attacks that fooled the detector, per round")
            st.line_chart(df, height=170)
        else:
            st.info("Run `python scripts/run_arms_race.py` to populate this.")

# ── step 2: results ──────────────────────────────────────────────────────────
text = st.session_state.get("email_text", "")
if analyse and text.strip():
    with st.spinner("Scanning for phishing indicators…"):
        prob = float(detector.predict_proba([text])[0])
        is_phish = prob >= detector.threshold
        band, band_color = risk_band(prob)

    st.write("")
    with st.container(border=True):
        st.markdown('<span class="step">Step 2 — the verdict</span>', unsafe_allow_html=True)
        v1, v2 = st.columns([1.25, 1], gap="large")
        with v1:
            color = RED if is_phish else GREEN
            label = "⚠️  Likely phishing" if is_phish else "✓  Looks legitimate"
            st.markdown(f'<div class="verdict" style="background:{color};">{label}</div>',
                        unsafe_allow_html=True)
            st.markdown(f"<div style='margin-top:.8rem'><b style='font-size:1.05rem'>Risk score "
                        f"{prob:.0%}</b> &nbsp;<span class='pill' style='background:{band_color}22;"
                        f"color:{band_color};'>{band}</span></div>", unsafe_allow_html=True)
            st.markdown(f'<div class="meter"><div class="meter-fill" '
                        f'style="width:{prob*100:.0f}%;background:{band_color};"></div></div>',
                        unsafe_allow_html=True)
        with v2:
            reasons = reasons_for(text)
            if is_phish:
                st.markdown("**Why it was flagged**")
                if reasons:
                    for title, why in reasons:
                        st.markdown(f'<div class="reason"><b>{title}</b><br><span>{why}</span></div>',
                                    unsafe_allow_html=True)
                else:
                    st.markdown('<div class="reason"><span>Flagged by its overall wording patterns.'
                                '</span></div>', unsafe_allow_html=True)
            else:
                st.markdown("**Why it looks safe**")
                if reasons:
                    st.markdown('<div class="reason"><span>A few mild signals are present, but not '
                                'enough to flag it:</span></div>', unsafe_allow_html=True)
                    for title, why in reasons:
                        st.markdown(f'<div class="reason"><b>{title}</b><br><span>{why}</span></div>',
                                    unsafe_allow_html=True)
                else:
                    st.markdown('<div class="reason"><span>No strong phishing signals — reads like '
                                'ordinary text.</span></div>', unsafe_allow_html=True)
elif analyse:
    st.info("Please paste some email text first.")
else:
    st.write("")
    st.info("👆 Press **Analyse email** above — the phishing example is preloaded, so you can try it right now.")

# ── optional: live Gmail inbox scan ──────────────────────────────────────────
st.write("")
with st.container(border=True):
    st.markdown('<span class="step">Optional</span>', unsafe_allow_html=True)
    st.markdown("#### Scan a live inbox")
    st.caption("Connect a Gmail account to flag phishing in your real inbox. Credentials are read "
               "from a `.env` file and never stored in the code.")
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env")
    except ImportError:
        pass
    addr, pw = os.getenv("GMAIL_ADDRESS"), os.getenv("GMAIL_APP_PASSWORD")
    if not addr or not pw:
        st.info("To enable: copy `.env.example` to `.env`, add your Gmail address and "
                "[App Password](https://support.google.com/accounts/answer/185833), then reload.")
    elif st.button("Scan my inbox", type="primary"):
        from gmail_scan import fetch_latest_emails

        with st.spinner("Connecting to Gmail…"):
            emails = fetch_latest_emails(addr, pw, os.getenv("IMAP_SERVER", "imap.gmail.com"), n=30)
        if isinstance(emails, str):
            st.error(emails)
        else:
            probs = detector.predict_proba(emails)
            df = pd.DataFrame({
                "Verdict": ["Phishing" if p >= detector.threshold else "Legit" for p in probs],
                "Risk": [f"{p:.0%}" for p in probs],
                "Email (preview)": [e[:90] for e in emails],
            })
            st.success(f"Scanned {len(df)} emails — {int((probs >= detector.threshold).sum())} flagged.")
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("Download results", df.to_csv(index=False), "scan_results.csv", "text/csv")

st.markdown(f'<p class="foot">PhishArms · adversarial machine learning for email security · '
            f'<a href="{GITHUB_URL}">GitHub</a></p>', unsafe_allow_html=True)
