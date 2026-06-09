"""Make stdout/stderr UTF-8 so the project's emoji/box-drawing output and logs
render on every platform (Windows consoles default to cp1252 and would crash)."""

from __future__ import annotations

import sys


def enable_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
