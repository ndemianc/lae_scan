"""Known vulnerability events. Any other event can be given on the command line
with --event NAME --cve ID [--cve ID ...] --t0 TIMESTAMP."""
from __future__ import annotations

from .model import Event

KNOWN = {
    # Disclosure and fixed releases on 2026-10-21 (php.net announcements, GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp)
    "PHP2Shell": {"cves": ("CVE-2026-109618", "CVE-2026-109619"), "t0": "2026-10-21T14:00:00Z"},
}


def get(name: str, cves=(), t0: str = "", horizon_days: int = 90) -> Event:
    known = KNOWN.get(name, {})
    cves = tuple(cves) or known.get("cves", ())
    t0 = t0 or known.get("t0", "")
    if not cves or not t0:
        raise ValueError(f"unknown event {name!r}: give --cve and --t0")
    return Event(name=name, cves=cves, t0=Event.parse_t0(t0), horizon_days=horizon_days)
