"""PhishArms — self-evolving phishing defense dashboard.
Clean, card-based, with live attacker simulation and vibrant UI.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phisharms.attacker import RedTeam  # noqa: E402
from phisharms.detector import PhishingDetector  # noqa: E402
from phisharms.features import _SPAM_KEYWORDS, _URGENCY_WORDS, extract_features  # noqa: E402

GITHUB_URL = "https://github.com/Muskan-2504/phishing-arms-race"

# 🎨 VIBRANT COLOR PALETTE
DANGER = "#DC2626"      # bright red for phishing
SUCCESS = "#10B981"     # emerald green for legit
WARNING = "#F59E0B"     # amber for medium risk
PRIMARY = "#6366F1"     # indigo for buttons
SECONDARY = "#8B5CF6"   # purple for accents
DARK = "#1E293B"        # slate for text
CARD_BG = "#FFFFFF"     # white cards
ACCENT_1 = "#EC4899"    # pink for attacker section
ACCENT_2 = "#06B6D4"    # cyan for track record
ACCENT_3 = "#F97316"    # orange for quick tests

st.set_page_config(page_title="PhishArms | Self-Evolving Phishing Defense", page_icon="🛡️", layout="wide")

st.markdown(
    f"""
    <style>
      #MainMenu, header, footer {{visibility: hidden;}}
      .block-container {{padding-top: 1.2rem; max-width: 1200px;}}
      h1, h2, h3, p {{color: {DARK};}}

      /* Card styling */
      div[data-testid="stVerticalBlockBorderWrapper"] {{
        border-radius: 20px !important;
        border: none !important;
        background: {CARD_BG} !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05), 0 1px 2px rgba(0,0,0,0.03) !important;
        padding: 0.5rem 1rem 1rem 1rem !important;
      }}

      .brand {{font-size: 1.8rem; font-weight: 800; background: linear-gradient(135deg, {PRIMARY}, {SECONDARY}); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin:0;}}
      .tagline {{color:#64748B; margin-top:-0.2rem; font-size:0.95rem;}}
      .step {{font-size:0.7rem; font-weight:600; letter-spacing:0.05em; color:{PRIMARY}; text-transform:uppercase; margin-bottom:0.2rem;}}

      /* Verdict cards */
      .verdict {{padding:1rem 1.2rem; border-radius:16px; font-weight:700; font-size:1.3rem; color:white; box-shadow: 0 2px 8px rgba(0,0,0,0.1);}}
      .phishing-verdict {{background: linear-gradient(135deg, {DANGER}, #EF4444);}}
      .legit-verdict {{background: linear-gradient(135deg, {SUCCESS}, #34D399);}}

      .pill {{display:inline-block; padding:0.2rem 0.8rem; border-radius:999px; font-size:0.7rem; font-weight:600;}}
      .pill-high {{background: {DANGER}20; color: {DANGER};}}
      .pill-med {{background: {WARNING}20; color: {WARNING};}}
      .pill-low {{background: {SUCCESS}20; color: {SUCCESS};}}

      .meter {{height:10px; width:100%; background:#E2E8F0; border-radius:999px; overflow:hidden; margin:0.3rem 0 0.5rem 0;}}
      .meter-fill {{height:100%; border-radius:999px; transition: width 0.3s ease;}}

      .reason {{padding:0.5rem 0; border-bottom:1px solid #F1F5F9;}}
      .reason b {{color:{DARK}; font-size:0.85rem;}}
      .reason span {{color:#64748B; font-size:0.75rem;}}

      .foot {{color:#94A3B8; font-size:0.7rem; text-align:center; margin-top:1.5rem;}}

      /* Metric cards */
      .metric-card {{background: linear-gradient(135deg, {ACCENT_2}10, {PRIMARY}05); border-radius: 16px; padding: 0.8rem; text-align: center;}}
      .metric-value {{font-size: 1.8rem; font-weight: 800; color: {PRIMARY};}}
      .metric-label {{font-size: 0.7rem; color: #64748B;}}
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

QUICK_TESTS = [
    ("💳 Bank scam", "Your Wells Fargo account is locked. Verify now: http://bit.ly/wells-fargo"),
    ("📦 Package", "UPS: confirm your address for delivery: http://tinyurl.com/ups-delivery"),
    ("💰 IRS refund", "You have a tax refund pending. Click here to claim: http://bit.ly/irs-refund"),
    ("🎁 Gift card", "Free $100 Amazon gift card! Claim now: http://bit.ly/amazon-gift"),
]


def matched(words, text: str) -> list[str]:
    low = text.lower()
    return [w for w in words if w in low]


def reasons_for(text: str) -> list[tuple[str, str]]:
    f = extract_features(text)
    out = []
    if f["has_url_shortener"]:
        out.append(("🔗 Shortened link", "hides the real destination"))
    if f["has_ip_url"]:
        out.append(("🌐 Raw IP link", "real companies use named domains"))
    if f["num_links"]:
        out.append((f"📎 {int(f['num_links'])} link(s)", "phishing wants you to click"))
    urg = matched(_URGENCY_WORDS, text)
    if urg:
        out.append((f"⏰ Urgency: “{'”, “'.join(urg[:3])}”", "rushes you into a mistake"))
    spam = matched(_SPAM_KEYWORDS, text)
    if len(spam) >= 2:
        out.append((f"⚠️ Keywords: “{'”, “'.join(spam[:3])}”", "asks for account details"))
    if f["leetspeak_score"] >= 2:
        out.append(("🤖 Leetspeak (p@yp4l)", "dodges keyword filters"))
    if f["homoglyph_score"]:
        out.append(("🪄 Look-alike characters", "Cyrillic/Greek imitating English"))
    if f["zero_width_count"]:
        out.append(("👻 Hidden invisible chars", "inserted to break up flagged words"))
    if f["capital_ratio"] > 0.30:
        out.append(("📢 Excessive capitals", "shouting is common in scams"))
    return out


def risk_band(prob: float) -> tuple[str, str, str]:
    if prob >= 0.70:
        return "High risk", DANGER, "pill-high"
    if prob >= 0.40:
        return "Medium risk", WARNING, "pill-med"
    return "Low risk", SUCCESS, "pill-low"


detector, model_date = load_detector()
history = load_history()

# Header with gradient
hl, hr = st.columns([3, 1])
with hl:
    st.markdown('<p class="brand">🛡️ PhishArms</p>', unsafe_allow_html=True)
    st.markdown('<p class="tagline">A phishing detector that trains against an attacker trying to '
                'beat it — and gets stronger every round.</p>', unsafe_allow_html=True)
with hr:
    st.write("")
    st.markdown(f"<div style='text-align:right'><a href='{GITHUB_URL}' style='color:{PRIMARY};'>📖 Source on GitHub →</a></div>",
                unsafe_allow_html=True)

if detector is None:
    st.warning("⚠️ No trained model found. Run `python scripts/train_baseline.py` first.")
    st.stop()

# Input + Track Record
col_in, col_eval = st.columns([1.3, 1], gap="large")

with col_in:
    with st.container(border=True):
        st.markdown(f'<span class="step" style="color:{PRIMARY};">📥 Step 1 — Try it</span>', unsafe_allow_html=True)
        st.markdown("#### Check an email")

        if "email_text" not in st.session_state:
            st.session_state.email_text = PHISHING_SAMPLE

        # Colorful buttons
        b1, b2, b3 = st.columns(3)
        with b1:
            st.button("📧 Phishing", use_container_width=True, type="primary" if st.session_state.email_text == PHISHING_SAMPLE else "secondary",
                     on_click=lambda: st.session_state.update({"email_text": PHISHING_SAMPLE}))
        with b2:
            st.button("✅ Safe", use_container_width=True, on_click=lambda: st.session_state.update({"email_text": SAFE_SAMPLE}))
        with b3:
            st.button("🗑️ Clear", use_container_width=True, on_click=lambda: st.session_state.update({"email_text": ""}))

        st.text_area("Email body", key="email_text", height=160, label_visibility="collapsed")

        # Quick test buttons with color
        st.markdown(f"<span style='color:{ACCENT_3}; font-size:0.7rem; font-weight:600;'>⚡ QUICK TESTS</span>", unsafe_allow_html=True)
        cols = st.columns(4)
        for col, (label, body) in zip(cols, QUICK_TESTS):
            if col.button(label, use_container_width=True):
                st.session_state.email_text = body
                st.rerun()

        analyse = st.button("🔍 Analyse email", type="primary", use_container_width=True)

with col_eval:
    with st.container(border=True):
        st.markdown(f'<span class="step" style="color:{ACCENT_2};">📊 Proof it learns</span>', unsafe_allow_html=True)
        st.markdown("#### Detector track record")
        if history:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f'<div class="metric-card"><div class="metric-value">{history[0]["evasion_rate_before"]:.0%}</div><div class="metric-label">Evasion rate (round 1)</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:{SUCCESS};">{history[-1]["evasion_rate_before"]:.0%}</div><div class="metric-label">Evasion rate (final)</div></div>', unsafe_allow_html=True)

            df = pd.DataFrame({"Evasion %": [h["evasion_rate_before"] * 100 for h in history]},
                              index=[f"Round {h['generation']}" for h in history])
            st.caption("📉 Attacks that fooled the detector")
            st.line_chart(df, height=140, color=[PRIMARY])
        else:
            st.info("Run `python scripts/run_arms_race.py` to see evolution.")

# Results
text = st.session_state.get("email_text", "")
if analyse and text.strip():
    with st.spinner("🔎 Scanning for phishing indicators..."):
        prob = float(detector.predict_proba([text])[0])
        is_phish = prob >= detector.threshold
        band, band_color, pill_class = risk_band(prob)

    st.write("")
    with st.container(border=True):
        st.markdown(f'<span class="step" style="color:{SECONDARY};">⚖️ Step 2 — The verdict</span>', unsafe_allow_html=True)
        v1, v2 = st.columns([1.2, 1], gap="large")
        with v1:
            if is_phish:
                st.markdown('<div class="verdict phishing-verdict">⚠️ Likely phishing</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="verdict legit-verdict">✓ Looks legitimate</div>', unsafe_allow_html=True)

            st.markdown(f"<div><b style='font-size:1.1rem;'>Risk score {prob:.0%}</b> "
                        f"<span class='pill {pill_class}'>{band}</span></div>", unsafe_allow_html=True)
            st.markdown(f'<div class="meter"><div class="meter-fill" '
                        f'style="width:{prob*100:.0f}%;background:{band_color};"></div></div>',
                        unsafe_allow_html=True)
            if model_date:
                st.caption(f"🗓️ Model: {model_date.strftime('%b %d, %Y')}")
        with v2:
            reasons = reasons_for(text)
            if is_phish:
                st.markdown("**🚨 Why it was flagged**")
                if reasons:
                    for title, why in reasons:
                        st.markdown(f'<div class="reason"><b>{title}</b><br><span>{why}</span></div>',
                                    unsafe_allow_html=True)
                else:
                    st.markdown('<div class="reason"><span>Flagged by overall pattern matching.</span></div>',
                                unsafe_allow_html=True)
            else:
                st.markdown("**✅ Why it looks safe**")
                if reasons:
                    st.markdown('<div class="reason"><span>Mild signals present, but not enough to flag:</span></div>',
                                unsafe_allow_html=True)
                    for title, why in reasons[:2]:
                        st.markdown(f'<div class="reason"><b>{title}</b><br><span>{why}</span></div>',
                                    unsafe_allow_html=True)
                else:
                    st.markdown('<div class="reason"><span>No strong phishing signals detected.</span></div>',
                                unsafe_allow_html=True)

    # 🔴 Step 3: Attacker simulation — only meaningful for emails the detector flagged
    with st.container(border=True):
        st.markdown(f'<span class="step" style="color:{ACCENT_1};">🤖 Step 3 — Can an attacker fool it?</span>', unsafe_allow_html=True)
        st.markdown("#### 🔴 Red team attack simulation")

        if not is_phish:
            st.info("This email wasn't flagged as phishing, so there's nothing for the attacker to "
                    "disguise. Load the **📧 Phishing** example above to watch the Red team try to "
                    "evade detection.")
        else:
            st.caption("The attacker mutates this phishing email — leetspeak, look-alike characters, "
                       "hidden spaces — trying to push its risk below the detection line while keeping "
                       "it readable.")
            ATTEMPTS = 12
            with st.spinner("Attempting to evade detection..."):
                red = RedTeam(attempts_per_email=ATTEMPTS, seed=42)
                report = red.attack(detector, [text])

            if report.evasions:  # RedTeam only records attempts that fell below the threshold
                ev = min(report.evasions, key=lambda e: e.new_prob)
                st.error(f"⚠️ Attacker succeeded — risk dropped {ev.orig_prob:.0%} → {ev.new_prob:.0%}. "
                         "In the full arms race, this evasion is fed back via `harden()` and the "
                         "detector relearns to catch it.")
                with st.expander("🔓 See how they did it"):
                    st.markdown(f"**Mutation used:** `{', '.join(ev.ops)}`")
                    st.code(ev.mutated[:400])
            else:
                st.success(f"✅ Detector held strong — all {ATTEMPTS} evasion attempts failed. "
                           "This resilience is the payoff of training against the attacker over "
                           "many rounds.")

elif analyse:
    st.info("📝 Please paste some email text above first.")
else:
    st.info("👆 Press **Analyse email** — a phishing example is preloaded, so you can try it right now.")

# Optional: Gmail scan
st.write("")
with st.container(border=True):
    st.markdown(f'<span class="step" style="color:{SUCCESS};">📬 Optional</span>', unsafe_allow_html=True)
    st.markdown("#### Scan a live Gmail inbox")
    st.caption("Connect your Gmail to flag phishing in real emails. Credentials from `.env` only.")
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    except ImportError:
        pass
    addr, pw = os.getenv("GMAIL_ADDRESS"), os.getenv("GMAIL_APP_PASSWORD")
    if not addr or not pw:
        st.info("To enable: copy `.env.example` → `.env`, add Gmail address and App Password.")
    elif st.button("📬 Scan my inbox", type="primary"):
        from gmail_scan import fetch_latest_emails
        with st.spinner("Connecting to Gmail..."):
            emails = fetch_latest_emails(addr, pw, os.getenv("IMAP_SERVER", "imap.gmail.com"), n=30)
        if isinstance(emails, str):
            st.error(emails)
        else:
            probs = detector.predict_proba(emails)
            df = pd.DataFrame({
                "Verdict": ["🚨 Phishing" if p >= detector.threshold else "✅ Legit" for p in probs],
                "Risk": [f"{p:.0%}" for p in probs],
                "Preview": [e[:80] for e in emails],
            })
            st.success(f"Scanned {len(df)} emails — {int((probs >= detector.threshold).sum())} flagged.")
            st.dataframe(df, use_container_width=True, hide_index=True)

st.markdown(
    f'<p class="foot">🛡️ PhishArms · Adversarial ML for email security · '
    f'<a href="{GITHUB_URL}" style="color:{PRIMARY};">GitHub →</a></p>',
    unsafe_allow_html=True,
)
