"""Minimal IMAP fetch helper for the live Gmail tab.

Kept separate from the dashboard so it can be unit-tested and reused. Credentials
are passed in by the caller (which reads them from `.env`) — nothing is hardcoded.
"""

from __future__ import annotations

import email
import imaplib
import re

from bs4 import BeautifulSoup


def _clean(raw: str) -> str:
    try:
        text = BeautifulSoup(raw, "lxml").get_text()
        return re.sub(r"\s+", " ", text).strip()
    except Exception:
        return raw.strip()


def fetch_latest_emails(address: str, app_password: str, server: str = "imap.gmail.com", n: int = 30):
    """Return the bodies of the latest ``n`` inbox emails, or an error string."""
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(address, app_password)
        mail.select("inbox")
        _, messages = mail.search(None, "ALL")
        ids = messages[0].split()[-n:]

        bodies: list[str] = []
        for i in ids:
            _, data = mail.fetch(i, "(RFC822)")
            for part in data:
                if not isinstance(part, tuple):
                    continue
                msg = email.message_from_bytes(part[1])
                body = ""
                if msg.is_multipart():
                    for p in msg.walk():
                        disp = str(p.get("Content-Disposition"))
                        if p.get_content_type() == "text/plain" and "attachment" not in disp:
                            payload = p.get_payload(decode=True)
                            if payload:
                                body = payload.decode(errors="ignore")
                                break
                else:
                    payload = msg.get_payload(decode=True)
                    body = payload.decode(errors="ignore") if payload else ""
                bodies.append(_clean(body))
        mail.logout()
        return bodies
    except Exception as exc:  # noqa: BLE001 — surfaced to the UI
        return f"Error fetching emails: {exc}"
