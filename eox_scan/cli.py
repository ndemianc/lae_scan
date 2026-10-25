"""eox-scan command line.

  eox-scan snapshot build  --src data/snapshot-2026-10-22 --out build/snapshot --as-of 2026-10-22
  eox-scan scan  <sbom.json | image | dir>  --snapshot build/snapshot --event PHP2Shell
  eox-scan replay  --snapshot build/snapshot
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

from . import __version__, events, replay, sbom, writers
from .baseline import b1, b2_remediable, xeol_emulation
from .engine import EngineOptions, classify
from .snapshot import Snapshot
from .supplier import is_php

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _repo_path(*parts: str) -> str:
    """A repository file: next to the package (source checkout, editable install), else under the cwd."""
    p = os.path.join(ROOT, *parts)
    return p if os.path.exists(p) else os.path.join(os.getcwd(), *parts)


DEFAULT_SRC = _repo_path("data", "snapshot-2026-10-22")


def _event(a) -> events.Event:
    return events.get(a.event, cves=a.cve or (), t0=a.t0 or "", horizon_days=a.horizon)


def _opts(a) -> EngineOptions:
    kev = set()
    if getattr(a, "kev", None):
        with open(a.kev) as f:
            doc = json.load(f)
        kev = {v.get("cveID") for v in doc.get("vulnerabilities", [])}
    return EngineOptions(entitlements=set(a.entitlement or []), exploited_cves=kev)


def _group(pkgs):
    """One verdict per source build: php8.2-cli, php8.2-fpm, ... from source php8.2 at one version."""
    reps, covers, seen = [], {}, {}
    for p in pkgs:
        key = (p.ptype, p.namespace, p.source_name or p.name, p.version, p.distro, p.vendor)
        if p.version is None or p.ptype == "generic":
            key = (p.ref,)
        if key in seen:
            covers[seen[key]].add(p.name)
            continue
        seen[key] = p.ref
        covers[p.ref] = {p.name}
        reps.append(p)
    return reps, covers


def _write(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    else:
        print(text)


def cmd_snapshot_build(a) -> int:
    from .snapshot.build import build
    files = build(a.src, a.out, a.as_of, a.openeox_schema or "")
    for rel, sha in files.items():
        print(f"{sha}  {rel}")
    print(f"snapshot written to {a.out}; import into xeol with: xeol db import {os.path.join(a.out, 'xeol-db_v1.tar.gz')}")
    return 0


def cmd_scan(a) -> int:
    snap = Snapshot.load(a.snapshot)
    ev = _event(a)
    target = a.target
    if not (os.path.isfile(target) and target.endswith(".json")):
        from .runners import syft
        fd, path = tempfile.mkstemp(suffix=".syft.json")
        os.close(fd)
        print(f"eox-scan: running syft on {target} ...", file=sys.stderr)
        syft.scan(target, path, allow_unpinned=a.allow_unpinned, timeout=a.syft_timeout)
        target = path
    pkgs, covers = _group([p for p in sbom.read(target) if is_php(p)])
    if not pkgs:
        print("no PHP packages found", file=sys.stderr)
    xeol_res = None
    if a.baseline == "xeol":
        from .runners import xeol
        xeol_res = xeol.scan(target, a.snapshot, lookahead=a.lookahead, allow_unpinned=a.allow_unpinned)
        xeol_res = xeol.expand_collapsed(pkgs, xeol_res)
    opts = _opts(a)
    verdicts = []
    for p in pkgs:
        v = classify(p, snap, ev, opts)
        if len(covers[p.ref]) > 1:
            v.notes.append("Same source build as binary packages: " + ", ".join(sorted(covers[p.ref])))
        if a.baseline != "none":
            xv = xeol_res.get(p.purl, {"verdict": "no_match"}) if xeol_res is not None else \
                xeol_emulation.match(p.version, snap, ev.t0.date())
            v.baseline = {"B1": b1(p, snap), "B2_remediable": b2_remediable(p, snap, ev),
                          "xeol": {**xv, "source": "binary" if xeol_res is not None else "emulation"}}
        verdicts.append(v)
    if a.format == "csaf-vex":
        text = json.dumps(writers.csaf_vex(verdicts, ev), indent=2)
    elif a.format == "table":
        text = writers.table(verdicts)
    else:
        text = json.dumps(writers.report_json(verdicts, ev, snap.as_of), indent=2, default=str)
    _write(text, a.output)
    fail = set(c.strip() for c in (a.fail_on_class or "").split(",") if c.strip())
    return 3 if fail and any(v.exposure_class in fail for v in verdicts) else 0


def cmd_replay(a) -> int:
    snap = Snapshot.load(a.snapshot)
    ev = _event(a)
    xeol_res = None
    if a.baseline == "xeol":
        from .runners import xeol
        # one xeol run per build: each build is a separate system, and a combined run would let xeol's
        # de-duplication by (cycle, version) hide builds that share a version string
        xeol_res = xeol.scan_each(a.sbom, a.snapshot, lookahead="", allow_unpinned=a.allow_unpinned)
        stale = xeol.stale_dates(snap, ev.t0.date())
        if stale:
            print("warning: xeol evaluates EoL at today's date, not T0; its verdicts can differ from the paper for "
                  + ", ".join(stale), file=sys.stderr)
    res = replay.run(a.sbom, a.truth, snap, ev, xeol_verdicts=xeol_res)
    if a.output:
        with open(a.output, "w") as f:
            json.dump(res, f, indent=1, default=str)
    print(replay.format_summary(res))
    return 0


def cmd_tools(a) -> int:
    from .runners import check
    rows = check(pin=a.pin)
    for r in rows:
        if not r["path"]:
            print(f"{r['tool']:<5} not found")
            continue
        state = "pinned" if r["pinned"] else "NOT pinned"
        print(f"{r['tool']:<5} {r['version'] or '?':<10} {state:<10} {r['sha256']}  {r['path']}")
    if a.pin:
        print("tools.lock updated. Compare the hashes above with the release checksum files before committing it.")
    return 0 if all(r["path"] for r in rows) else 1


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="eox-scan", description="Lifecycle-attributable exposure scanner (PHP PoC)")
    ap.add_argument("--version", action="version", version=f"eox-scan {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("snapshot", help="snapshot operations")
    ssub = sp.add_subparsers(dest="snapcmd", required=True)
    sb = ssub.add_parser("build", help="build eox.db, the xeol database and OpenEoX documents from CSV sources")
    sb.add_argument("--src", default=DEFAULT_SRC)
    sb.add_argument("--out", default=os.path.join("build", "snapshot"))
    sb.add_argument("--as-of", default="2026-10-22")
    sb.add_argument("--openeox-schema", help="path to the official OpenEoX core.json (optional, needs jsonschema)")
    sb.set_defaults(func=cmd_snapshot_build)

    def common(p):
        p.add_argument("--snapshot", default=DEFAULT_SRC, help="built snapshot dir, eox.db, or CSV source dir")
        p.add_argument("--event", default="PHP2Shell")
        p.add_argument("--cve", action="append", help="CVE id of the event (repeat); default from known events")
        p.add_argument("--t0", help="event time, RFC 3339; default from known events")
        p.add_argument("--horizon", type=int, default=90, help="K2 imminence horizon in days (default 90)")
        p.add_argument("--allow-unpinned", action="store_true", help="run tools whose hash is not in tools.lock")

    sc = sub.add_parser("scan", help="classify PHP packages in an SBOM, image or directory")
    sc.add_argument("target", help="Syft JSON or CycloneDX JSON file, or a Syft target: image (registry:IMAGE skips the "
                    "Docker daemon), dir:PATH, docker-archive:FILE, ...")
    common(sc)
    sc.add_argument("--baseline", choices=["none", "emulate", "xeol"], default="none",
                    help="also report baselines B1/B2 and xeol (emulated, or the real binary)")
    sc.add_argument("--syft-timeout", type=int, default=600, help="seconds to wait for syft (default 600)")
    sc.add_argument("--lookahead", default="",
                    help="xeol --lookahead when --baseline xeol (default: none, i.e. EoL before today)")
    sc.add_argument("--entitlement", action="append",
                    help="subscription tier you are entitled to, e.g. ubuntu:esm or freexian-elts (repeat)")
    sc.add_argument("--kev", help="CISA KEV JSON file for K13")
    sc.add_argument("--format", choices=["json", "csaf-vex", "table"], default="json")
    sc.add_argument("-o", "--output")
    sc.add_argument("--fail-on-class", help="exit 3 if any package is in one of these classes, e.g. E2,E3")
    sc.set_defaults(func=cmd_scan)

    tp = sub.add_parser("tools", help="show Syft and xeol paths, versions and hashes; --pin records them")
    tp.add_argument("--pin", action="store_true", help="write the found binaries' hashes into tools.lock")
    tp.set_defaults(func=cmd_tools)

    rp = sub.add_parser("replay", help="reproduce the paper's evaluation from scanner inputs")
    common(rp)
    rp.add_argument("--sbom", default=_repo_path("replay", "php2shell.cdx.json"))
    rp.add_argument("--truth", default=_repo_path("replay", "ground_truth.csv"))
    rp.add_argument("--baseline", choices=["emulate", "xeol"], default="emulate")
    rp.add_argument("-o", "--output")
    rp.set_defaults(func=cmd_replay)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    from .runners import ToolError
    a = parser().parse_args(argv)
    try:
        return a.func(a)
    except ToolError as e:
        print(f"eox-scan: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
