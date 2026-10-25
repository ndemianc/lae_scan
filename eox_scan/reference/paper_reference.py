#!/usr/bin/env python3
"""Lifecycle-Attributable Exposure (LAE) classifier.

Reference implementation of the EoX attribution criteria K1-K13 and the
E0-E3 classification, applied to PHP2Shell (CVE-2026-109618/109619).

Inputs (../data):
  php_branches.csv                  upstream lifecycle and remediation per branch
  population_mallory_2026-10-21.csv internet exposure by branch group
  builds.csv                        ground-truth package builds (vendor trackers)
  vendors.csv                       per-vendor machine-readable publication facts
Outputs (../results): JSON/CSV results and LaTeX table fragments.

Usage: python3 lae.py [--horizon 90]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, date

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
OUT = os.path.join(HERE, "..", "results")

# Event time: coordinated release of fixed versions (PHP security team).
T0 = datetime(2026, 10, 21, 14, 0, tzinfo=timezone.utc)
FIXED = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}

CLASS_ORDER = ["E0", "E1", "E2", "E3", "EX", "D+", "D~"]
CLASS_LABEL = {
    "E0": "Supported, release fix",
    "E1": "Fixed, EoSSec imminent",
    "E2": "EoSSec lapsed, source-only fix",
    "E3": "EoSSec lapsed, no fix",
    "EX": "Indeterminate provenance",
    "D+": "Downstream override, fixed",
    "D~": "Downstream override, pending",
}


def d(s: str):
    return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc) if s else None


def vtuple(s: str):
    out = []
    for p in s.split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


@dataclass
class BranchEval:
    branch: str
    K1_eol_lapsed: bool          # End-of-Life <= T0
    K2_eossec_state: str         # lapsed | imminent | active
    K3_remediation: str          # release | source | none
    K5_counterfactual: bool      # a supported branch receives a release fix
    K6_provenance: str           # confirmed | reported | conflicting | unconfirmed | unknown
    K7_lapse_days: int | None    # days between EoSSec and T0 (lapsed only)
    K7_residual: str             # bounded | unbounded
    eossec_days_left: int | None
    cls: str
    lifecycle_attributable: bool


def classify_branch(row: dict, horizon_days: int) -> BranchEval:
    eol, eoss = d(row["end_of_life"]), d(row["end_of_security_support"])
    k1 = eol is not None and eol <= T0
    if eoss is not None and eoss <= T0:
        k2 = "lapsed"
    elif eoss is not None and (eoss - T0).days <= horizon_days:
        k2 = "imminent"
    else:
        k2 = "active"
    k3 = row["upstream_fix"]
    k5 = True  # at least one supported branch (8.2-8.5) has a release fix
    k6 = row["provenance"]
    lapse = (T0 - eoss).days if k2 == "lapsed" else None
    left = (eoss - T0).days if k2 != "lapsed" else None
    residual = "bounded" if k3 == "release" else "unbounded"

    if k6 not in ("confirmed", "reported"):
        cls = "EX"
    elif k3 == "release" and k2 == "active":
        cls = "E0"
    elif k3 == "release" and k2 == "imminent":
        cls = "E1"
    elif k2 == "lapsed" and k3 == "source":
        cls = "E2"
    elif k2 == "lapsed" and k3 == "none":
        cls = "E3"
    else:
        cls = "E0"
    la = (k6 in ("confirmed", "reported")) and (k1 or k2 == "lapsed") and k3 in ("source", "none") and k5
    return BranchEval(row["branch"], k1, k2, k3, k5, k6, lapse, residual, left, cls, la)


def load_csv(name):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return []
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------- builds ----
def branch_of(v: str) -> str:
    t = vtuple(v)
    return f"{t[0]}.{t[1]}" if len(t) >= 2 else v


def truth_fixed(b: dict) -> bool | None:
    s = b["fix_status"].strip()
    if s == "fixed":
        return True
    if s in ("vulnerable", "pending", "will_not_fix"):
        return False
    return None  # not_affected / unknown excluded from fix-status scoring


def truth_remediable(b: dict) -> bool | None:
    """Will this build's own supplier deliver (or has delivered) a fix?"""
    s = b["fix_status"].strip()
    if s == "fixed":
        return True
    if s == "will_not_fix":
        return False
    sup = b["vendor_supports_branch"].strip()
    if s in ("vulnerable", "pending"):
        if sup == "yes":
            return True
        if sup == "no":
            return False
    return None


def b1_fixed(b):
    """Version-string scanner: compare banner version with upstream fixed release."""
    br = branch_of(b["upstream_version_string"])
    if br not in FIXED:
        return False
    return vtuple(b["upstream_version_string"])[:3] >= FIXED[br]


def b1_remediable(b):
    """Version-string scanner: remediable iff upstream ships a release for the branch."""
    return branch_of(b["upstream_version_string"]) in FIXED


def b2_remediable(b, branches):
    """Lifecycle-aware scanner (third-party upstream EoL table, no supplier scoping)."""
    br = branch_of(b["upstream_version_string"])
    row = branches.get(br)
    if row is None:
        return False
    eoss = d(row["end_of_security_support"])
    return eoss is not None and eoss > T0


def framework(b, vendor_mr):
    """Supplier-scoped statements: reads the build supplier's own statements.
    Returns (fixed, remediable, available) where available means the supplier
    publishes fix status in machine-readable form today."""
    avail = vendor_mr.get(b["vendor"], {}).get("fix_status_mr") == "yes"
    return truth_fixed(b), truth_remediable(b), avail


def prf(pred, truth, positive=True):
    tp = sum(1 for p, t in zip(pred, truth) if p == positive and t == positive)
    fp = sum(1 for p, t in zip(pred, truth) if p == positive and t != positive)
    fn = sum(1 for p, t in zip(pred, truth) if p != positive and t == positive)
    tn = sum(1 for p, t in zip(pred, truth) if p != positive and t != positive)
    n = len(truth)
    acc = (tp + tn) / n if n else float("nan")
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    return dict(n=n, tp=tp, fp=fp, fn=fn, tn=tn, accuracy=acc, precision=prec, recall=rec)


def classify_build(b, branches, horizon):
    """Algorithm 1 at build level. A downstream supplier that has shipped a fix
    (Def. 3(iii)) or publishes a commitment (K4) overrides the upstream class."""
    row = branches.get(b["upstream_branch"].strip())
    base = classify_branch(row, horizon).cls if row else "EX"
    fixed = b["fix_status"].strip() == "fixed"
    committed = b["vendor_supports_branch"].strip() == "yes"
    if base in ("E2", "E3") and (fixed or committed):
        return "D+" if fixed else "D~"
    return base


# ------------------------------------------------------------ population ----
def population(branches, horizon):
    """Decompose Mallory's branch-group counts into LAE classes.
    The 5.2-5.6 group mixes EX branches (5.2, 5.3 unconfirmed; 5.4 conflicting) with
    E3 branches (5.5, 5.6) and no per-branch split is published, so it is reported
    as a mixed segment; only the Ubuntu 14.04 PHP 5.5.9 count is attributable to 5.5."""
    rows = load_csv("population_mallory_2026-10-21.csv")
    total = sum(int(r["services"]) for r in rows)
    v74 = 411000      # Mallory: "about 411,000" services on 7.4
    u1404 = 92000     # Mallory: about 92,000 services on PHP 5.5.9 (Ubuntu 14.04)
    u1404_pro = 247   # of which run an Ubuntu Pro build (class D)
    alloc = {"E0/E1": 0, "E2": 0, "E3": 0, "E3|EX": 0, "EX": 0, "D": 0}
    for r in rows:
        n = int(r["services"])
        g = r["group"]
        if g == "4.x-5.1":
            alloc["EX"] += n
        elif g == "5.2-5.6":
            alloc["E3"] += u1404 - u1404_pro
            alloc["D"] += u1404_pro
            alloc["E3|EX"] += n - u1404
        elif g == "7.x":
            alloc["E2"] += v74
            alloc["E3"] += n - v74
        elif g == "8.0-8.1":
            alloc["E2"] += n
        elif g == "8.2-8.5":
            alloc["E0/E1"] += n
    share = {k: v / total for k, v in alloc.items()}
    lo = alloc["E2"] + alloc["E3"]
    hi = lo + alloc["E3|EX"]
    return dict(total=total, alloc=alloc, share=share,
                lae_lower=lo, lae_lower_share=lo / total,
                lae_upper=hi, lae_upper_share=hi / total,
                le81_share=(total - alloc["E0/E1"]) / total,
                oct20_method_share=0.59, oct21_method_share=0.735, netlas_share=0.759,
                ubuntu1404_services=u1404, ubuntu1404_pro=u1404_pro,
                patch_adoption=[("15:22", 103), ("15:52", 144), ("17:15", 312), ("21:42", 2149)],
                patch_adoption_denominator=606000)


# ------------------------------------------------------------------ main ----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--horizon", type=int, default=90)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    branches = {r["branch"]: r for r in load_csv("php_branches.csv")}
    br_eval = [classify_branch(r, args.horizon) for r in branches.values()]
    with open(os.path.join(OUT, "branches_eval.json"), "w") as f:
        json.dump([asdict(e) for e in br_eval], f, indent=1)

    # Horizon sensitivity for E1
    sens = {}
    for h in (30, 60, 90, 180, 365):
        sens[h] = [e.branch for e in (classify_branch(r, h) for r in branches.values()) if e.cls == "E1"]

    pop = population(branches, args.horizon)

    all_rows = load_csv("builds.csv")
    vendors = {r["vendor"]: r for r in load_csv("vendors.csv")}
    res = {"horizon": args.horizon, "e1_sensitivity": sens, "population": pop}

    def eligible(b, include_derived=False):
        # installable builds only: exclude upstream branch-level rows, pre-releases,
        # per-CVE-only rows, and rows whose label was derived by version comparison
        if b["build_id"] in ("B005", "B006", "B007", "B008", "B009"):
            return False
        if b["cve_scope"].strip() != "both":
            return False
        if (not include_derived) and "[derived]" in b["status_detail"]:
            return False
        br = b["upstream_branch"].strip()
        return br in branches

    def evaluate(builds):
        out = {}
        fx = [(b, truth_fixed(b)) for b in builds if b["upstream_version_string"].strip()]
        fx = [(b, t) for b, t in fx if t is not None]
        truth = [t for _, t in fx]

        def ft_fixed(b):
            fxd, _, av = framework(b, vendors)
            return fxd if av else b1_fixed(b)

        out["fix_status"] = {
            "B1": prf([b1_fixed(b) for b, _ in fx], truth),
            "B2": prf([b1_fixed(b) for b, _ in fx], truth),
            "F_today": prf([ft_fixed(b) for b, _ in fx], truth),
            "F_full": prf(truth, truth),
        }
        rm = [(b, truth_remediable(b)) for b in builds]
        rm = [(b, t) for b, t in rm if t is not None]
        rtruth = [t for _, t in rm]

        def ft_rem(b):
            # machine-readable "fixed" implies remediable; otherwise the supplier's
            # commitment is usable only if its lifecycle is machine-readable
            fxd, r, av = framework(b, vendors)
            if av and fxd:
                return True
            lc = vendors.get(b["vendor"], {}).get("lifecycle_mr") == "yes"
            return r if (av and lc) else b2_rem(b)

        out["remediability"] = {
            "B1": prf([b1_rem(b) for b, _ in rm], rtruth),
            "B2": prf([b2_rem(b) for b, _ in rm], rtruth),
            "F_today": prf([ft_rem(b) for b, _ in rm], rtruth),
            "F_full": prf(rtruth, rtruth),
        }
        anat = {"fixed_but_old_string": 0, "vuln_but_new_string": 0}
        for b, t in fx:
            p = b1_fixed(b)
            if t and not p:
                anat["fixed_but_old_string"] += 1
            if (not t) and p:
                anat["vuln_but_new_string"] += 1
        out["b1_fix_error_anatomy"] = anat
        ranat = {"remediable_on_upstream_eol": 0, "not_remediable_on_supported": 0}
        for b, t in rm:
            if t and not b2_rem(b):
                ranat["remediable_on_upstream_eol"] += 1
            if (not t) and b2_rem(b):
                ranat["not_remediable_on_supported"] += 1
        out["b2_rem_error_anatomy"] = ranat
        by_str = {}
        for b, t in fx:
            by_str.setdefault(b["upstream_version_string"], set()).add(t)
        amb = sorted([s for s, ts in by_str.items() if len(ts) > 1], key=vtuple)
        out["k9_ambiguous_strings"] = amb
        out["k9_builds_on_ambiguous"] = sum(1 for b, _ in fx if b["upstream_version_string"] in amb)
        out["n_fix_scored"] = len(fx)
        out["n_rem_scored"] = len(rm)
        out["n_builds"] = len(builds)
        out["n_vendors"] = len({b["vendor"] for b in builds})
        out["mr_fix_cov"] = sum(1 for b in builds if vendors.get(b["vendor"], {}).get("fix_status_mr") == "yes") / len(builds)
        out["mr_both_cov"] = sum(1 for b in builds if vendors.get(b["vendor"], {}).get("fix_status_mr") == "yes"
                                 and vendors.get(b["vendor"], {}).get("lifecycle_mr") == "yes") / len(builds)
        out["openeox_cov"] = sum(1 for b in builds if vendors.get(b["vendor"], {}).get("openeox") == "yes") / len(builds)
        bc = {}
        for b in builds:
            c = classify_build(b, branches, args.horizon)
            b["lae_class"] = c
            bc[c] = bc.get(c, 0) + 1
        out["build_classes"] = bc
        # upstream-only classification of the same builds (no K4)
        bcu = {}
        for b in builds:
            c = classify_branch(branches[b["upstream_branch"].strip()], args.horizon).cls
            bcu[c] = bcu.get(c, 0) + 1
        out["build_classes_upstream_only"] = bcu
        return out

    def b1_rem(b):
        return b["upstream_branch"].strip() in FIXED

    def b2_rem(b):
        row = branches.get(b["upstream_branch"].strip())
        eoss = d(row["end_of_security_support"]) if row else None
        return eoss is not None and eoss > T0

    primary = [b for b in all_rows if eligible(b)]
    withder = [b for b in all_rows if eligible(b, include_derived=True)]
    res["primary"] = evaluate(primary)
    res["with_derived"] = evaluate(withder)
    res["n_rows_collected"] = len(all_rows)
    res["n_vendors_collected"] = len({b["vendor"] for b in all_rows})
    res["n_derived"] = sum(1 for b in all_rows if "[derived]" in b["status_detail"])
    res["fix_status_counts_all"] = {}
    for b in all_rows:
        res["fix_status_counts_all"][b["fix_status"]] = res["fix_status_counts_all"].get(b["fix_status"], 0) + 1
    with open(os.path.join(OUT, "builds_scored.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(primary[0].keys()))
        w.writeheader()
        w.writerows(primary)

    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(res, f, indent=1, default=str)
    print(json.dumps({k: v for k, v in res.items() if k not in ("population",)}, indent=1, default=str))
    print("population:", json.dumps({k: pop[k] for k in ("total", "alloc", "share",
          "lae_lower_share", "lae_upper_share", "le81_share")}, indent=1))
    for e in br_eval:
        print(e.branch, e.cls, e.K2_eossec_state, e.K3_remediation, e.K6_provenance, e.K7_lapse_days, e.eossec_days_left, e.lifecycle_attributable)


if __name__ == "__main__":
    main()
