"""Faithful emulation of xeol's version-to-cycle matcher.

Ported from xeol/search/purl.go (normalizeSemver, returnMatchingCycle,
cycleMatch) at commit fec1277, with the exact Masterminds/semver v1.5.0
version regex. Used when the xeol binary is not available, and to document
the matcher's fail-open behaviour: a version that semver v1 cannot parse makes
xeol log a warning and return no match.

Only two-component release cycles (PHP's "8.2") are needed here.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Dict, Optional

from ..snapshot import Snapshot

SEMVER_V1 = re.compile(r"^v?([0-9]+)(\.[0-9]+)?(\.[0-9]+)?"
                       r"(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?"
                       r"(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?$")


def normalize_semver(v: str) -> str:
    v = re.sub(r"^(\d+\.\d+\.\d+)p\d+", r"\1", v)
    v = re.sub(r"^(\d+\.\d+\.\d+)\.\w+", r"\1", v)
    return re.sub(r"^(\d+\.\d+\.\d+)-\d+~\w+", r"\1", v)


def match(version: Optional[str], snap: Snapshot, match_date: date) -> Dict[str, Optional[str]]:
    """Return {'verdict': eol|not_eol|no_match|parse_error, 'cycle': '8.2'|None, 'eol': 'YYYY-MM-DD'|None}."""
    if not version:
        return {"verdict": "no_match", "cycle": None, "eol": None}
    m = SEMVER_V1.match(normalize_semver(version))
    if not m:
        return {"verdict": "parse_error", "cycle": None, "eol": None}
    major, minor = int(m.group(1)), int((m.group(2) or ".0")[1:])
    for ub in snap.upstream.values():
        cmaj, cmin = (int(x) for x in ub.branch.split("."))
        if (major, minor) == (cmaj, cmin):
            eol = ub.end_of_security_support
            if eol is None:
                return {"verdict": "not_eol", "cycle": ub.branch, "eol": None}
            verdict = "eol" if match_date > eol else "not_eol"
            return {"verdict": verdict, "cycle": ub.branch, "eol": eol.isoformat()}
    return {"verdict": "no_match", "cycle": None, "eol": None}


def match_with_lookahead(version: Optional[str], snap: Snapshot, now: date, lookahead_days: int):
    return match(version, snap, now + timedelta(days=lookahead_days))
