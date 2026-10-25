"""Replay the paper's PHP2Shell evaluation from scanner inputs.

Unlike the paper's script, which scores the frameworks against the labels
themselves (F_full = truth), the replay derives every prediction from the
SBOM and the snapshot through the engine, and only then compares with the
labels in ground_truth.csv. Matching the paper's numbers is therefore a test
of the engine, not a restatement of the data.

Scored populations follow the paper: installable builds only (B005-B009
excluded), both CVEs in scope, and the primary set without labels derived by
version comparison ([derived]); `with_derived` adds them back.

Predictors:
  B1        upstream version string vs the upstream fixed release (fix status);
            branch has an upstream release fix (remediability)
  B2        upstream End-of-Security-Support after T0 (remediability; fix status as B1)
  B2_xeol   xeol's own matcher (binary or emulation): remediable unless xeol reports EoL
  F_today   engine on the machine-readable supplier data only
  F_full    engine on all supplier data in the snapshot
When the engine has no supplier statement for a build (fix status unknown),
the fix-status prediction falls back to B1, as in the paper.
"""
from __future__ import annotations

import csv
import math
from typing import Callable, Dict, List, Optional

from . import sbom
from .baseline import b1, b2_remediable
from .baseline import xeol_emulation
from .engine import EngineOptions, classify
from .model import Event, Package, Verdict
from .snapshot import Snapshot


def prf(pred: List[bool], truth: List[bool]) -> Dict:
    tp = sum(1 for p, t in zip(pred, truth) if p and t)
    fp = sum(1 for p, t in zip(pred, truth) if p and not t)
    fn = sum(1 for p, t in zip(pred, truth) if not p and t)
    tn = sum(1 for p, t in zip(pred, truth) if not p and not t)
    n = len(truth)

    def div(a, b):
        return a / b if b else math.nan
    return dict(n=n, tp=tp, fp=fp, fn=fn, tn=tn, accuracy=div(tp + tn, n), precision=div(tp, tp + fp),
                recall=div(tp, tp + fn))


def _bool(s: str) -> Optional[bool]:
    return {"true": True, "false": False}.get((s or "").strip().lower())


def _fixed_pred(v: Verdict, pkg: Package, snap: Snapshot) -> bool:
    if v.fix_status in ("fixed", "vulnerable"):
        return v.fix_status == "fixed"
    return bool(b1(pkg, snap)["fixed"])


def run(sbom_path: str, truth_csv: str, snap: Snapshot, event: Event,
        xeol_verdicts: Optional[Dict[str, Dict]] = None, opts: Optional[EngineOptions] = None) -> Dict:
    pkgs = {p.ref: p for p in sbom.read(sbom_path)}
    with open(truth_csv, newline="") as f:
        truth = [r for r in csv.DictReader(f)]
    today = snap.restricted_to_machine_readable()
    rows = []
    for t in truth:
        p = pkgs.get(t["build_id"])
        if p is None:
            continue
        v_full = classify(p, snap, event, opts)
        v_today = classify(p, today, event, opts)
        if xeol_verdicts is not None:
            xv = xeol_verdicts.get(p.purl, {"verdict": "no_match"})
        else:
            xv = xeol_emulation.match(p.version and _xeol_version(p), snap, event.t0.date())
        rows.append({"truth": t, "pkg": p, "full": v_full, "today": v_today, "xeol": xv})

    def eligible(r, include_derived):
        t = r["truth"]
        return t["eligible"] == "true" and r["full"].upstream_branch in snap.upstream and \
            (include_derived or t["derived"] != "true")

    res = {"event": event.name, "t0": event.t0.isoformat(), "snapshot": snap.as_of,
           "b2_xeol_source": "binary" if xeol_verdicts is not None else "emulation"}
    for name, inc in (("primary", False), ("with_derived", True)):
        rs = [r for r in rows if eligible(r, inc)]
        res[name] = _evaluate(rs, snap, event)
    res["builds"] = [_row_out(r, snap, event) for r in rows]
    return res


def _xeol_version(p: Package) -> str:
    """xeol matches the package version string as the SBOM gives it."""
    return p.version


def _evaluate(rs: List[Dict], snap: Snapshot, event: Event) -> Dict:
    out: Dict = {"n_builds": len(rs)}
    fx = [r for r in rs if r["truth"]["upstream_version_string"] and _bool(r["truth"]["truth_fixed"]) is not None]
    ft = [_bool(r["truth"]["truth_fixed"]) for r in fx]
    b1f: Callable = lambda r: bool(b1(r["pkg"], snap)["fixed"])  # noqa: E731
    out["fix_status"] = {
        "B1": prf([b1f(r) for r in fx], ft),
        "B2": prf([b1f(r) for r in fx], ft),
        "F_today": prf([_fixed_pred(r["today"], r["pkg"], snap) for r in fx], ft),
        "F_full": prf([_fixed_pred(r["full"], r["pkg"], snap) for r in fx], ft),
    }
    rm = [r for r in rs if _bool(r["truth"]["truth_remediable"]) is not None]
    rt = [_bool(r["truth"]["truth_remediable"]) for r in rm]
    out["remediability"] = {
        "B1": prf([b1(r["pkg"], snap)["remediable"] for r in rm], rt),
        "B2": prf([bool(b2_remediable(r["pkg"], snap, event)) for r in rm], rt),
        "B2_xeol": prf([r["xeol"]["verdict"] != "eol" for r in rm], rt),
        "F_today": prf([r["today"].remediable for r in rm], rt),
        "F_full": prf([r["full"].remediable for r in rm], rt),
    }
    out["n_fix_scored"], out["n_rem_scored"] = len(fx), len(rm)
    classes: Dict[str, int] = {}
    for r in rs:
        classes[r["full"].exposure_class] = classes.get(r["full"].exposure_class, 0) + 1
    out["build_classes"] = dict(sorted(classes.items()))
    xeol_counts: Dict[str, int] = {}
    for r in rs:
        xeol_counts[r["xeol"]["verdict"]] = xeol_counts.get(r["xeol"]["verdict"], 0) + 1
    out["b2_xeol_verdicts"] = dict(sorted(xeol_counts.items()))
    return out


def _row_out(r: Dict, snap: Snapshot, event: Event) -> Dict:
    v, t = r["full"], r["truth"]
    return {"build_id": t["build_id"], "purl": r["pkg"].purl, "class": v.exposure_class, "class_today": r["today"].exposure_class,
            "fix_status": v.fix_status, "remediable": v.remediable, "supplier": v.supplier,
            "truth_fixed": t["truth_fixed"], "truth_remediable": t["truth_remediable"],
            "b1": b1(r["pkg"], snap), "b2_remediable": b2_remediable(r["pkg"], snap, event),
            "xeol": r["xeol"]["verdict"]}


def format_summary(res: Dict) -> str:
    lines = [f"Replay of {res['event']} (T0 {res['t0']}), snapshot {res['snapshot']}, "
             f"B2_xeol from {res['b2_xeol_source']}"]
    for pop in ("primary", "with_derived"):
        p = res[pop]
        lines.append(f"\n[{pop}] builds={p['n_builds']} classes={p['build_classes']} xeol={p['b2_xeol_verdicts']}")
        for task in ("fix_status", "remediability"):
            n = p["n_fix_scored"] if task == "fix_status" else p["n_rem_scored"]
            lines.append(f"  {task} (n={n})")
            lines.append("    predictor  acc    prec   recall  tp  fp  fn  tn")
            for k, m in p[task].items():
                lines.append(f"    {k:<9}  {m['accuracy']:.3f}  {m['precision']:.3f}  {m['recall']:.3f}  "
                             f"{m['tp']:>3} {m['fp']:>3} {m['fn']:>3} {m['tn']:>3}")
    return "\n".join(lines)
