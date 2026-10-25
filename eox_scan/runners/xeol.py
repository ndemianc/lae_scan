"""Run the unmodified xeol binary as baseline B2, offline, on eox-scan's
PHP-only database (schema v1) from the snapshot.

Two details of xeol's CLI (cmd/xeol/cli/options/xeol.go) matter here:
- The default lookahead is 1y, so the flag is always passed. "No lookahead" is
  `--lookahead=` (empty), which makes xeol match against the current time.
- xeol always evaluates EoL against the wall clock, never against an event
  time. `stale_dates` reports the lifecycle dates that fall between T0 and
  now, where the binary's verdicts can differ from a T0 evaluation.
- xeol de-duplicates matches by (release cycle, EoL data, package version)
  (xeol/match/matches.go, Fingerprint). Two packages with the same version in
  the same cycle produce one match, and the other package is missing from the
  output. `scan_each` runs xeol once per component so that independent builds
  (the replay) cannot hide each other; `expand_collapsed` marks the packages a
  single-image run folded into another match.

No API key is ever passed: with one, xeol sends results to the xeol.io API and
switches to a 3-year lookahead.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import date
from typing import Dict, List, Optional

from . import ToolError, find_tool, load_lock, run

NO_LOOKAHEAD = ("", "0", "0d", "none")


def cache_dir(snapshot_dir: str) -> str:
    cache = os.path.abspath(os.path.join(snapshot_dir, "xeol-cache"))
    if not os.path.isfile(os.path.join(cache, "1", "xeol.db")):
        raise ToolError(f"no xeol database under {snapshot_dir}. Build the snapshot first: "
                        f"eox-scan snapshot build --out {snapshot_dir}")
    return cache


def scan(sbom_path: str, snapshot_dir: str, lookahead: str = "", lock: Optional[Dict] = None,
         allow_unpinned: bool = False) -> Dict[str, Dict]:
    """Return {purl: {'verdict': 'eol', 'cycle': ..., 'eol': ...}} for every package xeol matched.

    Packages absent from the result were not matched by xeol (no product, no
    cycle, or a version its semver v1 parser rejected).
    """
    lock = lock if lock is not None else load_lock()
    xeol = find_tool("xeol", lock, allow_unpinned)
    env = {
        "XEOL_DB_CACHE_DIR": cache_dir(snapshot_dir),
        "XEOL_DB_AUTO_UPDATE": "false",
        "XEOL_DB_VALIDATE_AGE": "false",
        "XEOL_CHECK_FOR_APP_UPDATE": "false",
        "XEOL_API_KEY": "",
    }
    la = "--lookahead=" if lookahead.strip().lower() in NO_LOOKAHEAD else f"--lookahead={lookahead}"
    stdout = run([xeol, f"sbom:{os.path.abspath(sbom_path)}", "-o", "json", la], env=env)
    doc = json.loads(stdout) if stdout.strip() else {"matches": []}
    out = {}
    for m in doc.get("matches") or []:
        art = m.get("artifact", {})
        cyc = m.get("Cycle", {})
        out[art.get("purl", "")] = {"verdict": "eol", "cycle": cyc.get("ReleaseCycle"), "eol": cyc.get("Eol"),
                                   "product": cyc.get("ProductName")}
    return out


def stale_dates(snap, t0: date, today: Optional[date] = None) -> List[str]:
    """Upstream EoSSec dates in (t0, today]: xeol (wall clock) and a T0 evaluation disagree on those branches."""
    today = today or date.today()
    return sorted(f"PHP {u.branch} ({u.end_of_security_support})" for u in snap.upstream.values()
                  if u.end_of_security_support and t0 < u.end_of_security_support <= today)


def scan_each(sbom_path: str, snapshot_dir: str, lookahead: str = "", lock: Optional[Dict] = None,
              allow_unpinned: bool = False) -> Dict[str, Dict]:
    """Run xeol separately on every component of a CycloneDX SBOM (one system per component)."""
    with open(sbom_path) as f:
        doc = json.load(f)
    if doc.get("bomFormat") != "CycloneDX":
        raise ToolError("per-component xeol runs need a CycloneDX SBOM")
    out: Dict[str, Dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for i, c in enumerate(doc.get("components", [])):
            one = {k: v for k, v in doc.items() if k != "components"}
            one["components"] = [c]
            path = os.path.join(tmp, f"c{i}.cdx.json")
            with open(path, "w") as f:
                json.dump(one, f)
            out.update(scan(path, snapshot_dir, lookahead, lock, allow_unpinned))
    return out


def expand_collapsed(pkgs, matched: Dict[str, Dict]) -> Dict[str, Dict]:
    """Packages xeol left out because an identical (cycle, version) match was already reported."""
    by_version = {}
    for p in pkgs:
        if p.purl in matched:
            by_version.setdefault(p.version, (p.purl, matched[p.purl]))
    extra = {}
    for p in pkgs:
        if p.purl not in matched and p.version in by_version:
            purl, m = by_version[p.version]
            extra[p.purl] = {**m, "collapsed_into": purl}
    return {**matched, **extra}
