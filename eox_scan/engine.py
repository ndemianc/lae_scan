"""Exposure-class engine: criteria K1-K11 and Algorithm 1 for one package and one event.

Class semantics follow the paper's reference implementation
(eox_scan/reference/paper_reference.py, `classify_build`): the upstream class is
E0/E1/E2/E3/EX from upstream data; a downstream supplier override (D+ fixed,
D~ committed but not yet fixed) applies only to builds whose upstream branch
is past End-of-Security-Support (E2/E3).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Iterable, List, Optional, Set, Tuple

from .model import Event, Evidence, Package, Verdict
from .snapshot import Advisory, Snapshot, UpstreamBranch
from .supplier import SupplierContext, resolve, upstream_branch
from .versions import compare, upstream_part

AFFECTED_PROVENANCE = ("confirmed", "reported")
REMEDIABLE_CLASSES = ("E0", "E1", "D+", "D~")


@dataclass
class EngineOptions:
    entitlements: Set[str] = field(default_factory=set)   # e.g. {"ubuntu:esm", "freexian-elts:elts"}
    exploited_cves: Set[str] = field(default_factory=set)  # K13, e.g. from the CISA KEV feed


# ----------------------------------------------------------------- helpers
def upstream_class(ub: UpstreamBranch, t0: date, horizon_days: int) -> Tuple[str, str]:
    """(class, K2 state) from upstream lifecycle and remediation only."""
    if ub.provenance not in AFFECTED_PROVENANCE:
        return "EX", _k2(ub, t0, horizon_days)
    k2 = _k2(ub, t0, horizon_days)
    if k2 == "lapsed" and ub.remediation == "source":
        return "E2", k2
    if k2 == "lapsed" and ub.remediation == "none":
        return "E3", k2
    if ub.remediation == "release" and k2 == "imminent":
        return "E1", k2
    # E0 covers the rest, as in the paper's reference code: a supported branch with a release fix, a supported
    # branch whose fix is not out yet (it will come through normal updates), and an ended branch for which
    # upstream still published a release fix (a courtesy release; no further fixes are committed)
    return "E0", k2


def _k2(ub: UpstreamBranch, t0: date, horizon_days: int) -> str:
    e = ub.end_of_security_support
    if e is None:
        return "active"
    if e <= t0:
        return "lapsed"
    return "imminent" if (e - t0).days <= horizon_days else "active"


def counterfactual_k5(snap: Snapshot, t0: date) -> bool:
    return any(u.remediation == "release" and u.end_of_security_support and u.end_of_security_support > t0
               and u.provenance in AFFECTED_PROVENANCE for u in snap.upstream.values())


def _advisories(snap: Snapshot, ctx: SupplierContext, pkg: Package, branch: Optional[str], event: Event,
                families: Iterable[str]) -> List[Advisory]:
    names = {pkg.name} | ({pkg.source_name} if pkg.source_name else set())
    ids = {event.name, *event.cves}
    out = []
    for a in snap.advisories:
        if a.family not in families or a.package not in names or a.cve not in ids:
            continue
        if a.distro and a.distro != (ctx.distro or ""):
            continue
        if a.upstream_branch and branch and a.upstream_branch != branch:
            continue
        out.append(a)
    return out


def _tier_usable(t, pkg: Package, entitlements: Set[str], fixed_by: Optional[str]) -> bool:
    if t.access == "public":
        return True
    if f"{t.family}:{t.tier}" in entitlements or t.family in entitlements:
        return True
    # the installed build itself comes from the subscription channel
    if t.family == "ubuntu" and t.tier in ("esm", "legacy") and pkg.version and "+esm" in pkg.version:
        return True
    return fixed_by == t.family


# ------------------------------------------------------------------ engine
def classify(pkg: Package, snap: Snapshot, event: Event, opts: Optional[EngineOptions] = None) -> Verdict:
    opts = opts or EngineOptions()
    t0 = event.t0.date()
    ev: List[Evidence] = []
    notes: List[str] = []
    branch = upstream_branch(pkg)
    ctx = resolve(pkg)
    ub = snap.upstream.get(branch) if branch else None

    if ub is None:
        reason = "identity" if branch is None else "unknown_branch"
        return Verdict(pkg, event.name, "EX", "EX", False, "unknown", False, "unknown", branch,
                       criteria={"K6": "unknown", "K9": "unresolved", "reason": reason},
                       actions=["Establish the PHP branch of this artifact (version not identifiable)."],
                       notes=[f"EX: {reason}"])

    up_cls, k2 = upstream_class(ub, t0, event.horizon_days)
    ev.append(Evidence("K1/K2", f"PHP {ub.branch}: EoSSec {ub.end_of_security_support}, EoL {ub.end_of_life}",
                       ub.source_url, "php.net lifecycle"))
    ev.append(Evidence("K6", f"affectedness {ub.provenance}: {ub.provenance_basis}", ub.source_url))
    k5 = counterfactual_k5(snap, t0)
    if k2 == "lapsed" and up_cls == "E0":
        notes.append(f"Courtesy release: PHP {ub.branch} is past End-of-Security-Support but upstream released a "
                     "fix for this event. Update now; later vulnerabilities will not be fixed.")

    # ---- fix status and supplier remediation (K3 at the supplier, K4)
    fix_status, fixed_by, supplier_rem, k10 = "unknown", None, "unknown", "silent"
    supplier = ctx.families[0] if ctx.families else "unknown"
    committed_by: Optional[str] = None
    no_fix_stated = False

    if ctx.families == ["php"] or not ctx.families:
        # upstream build (generic purl, e.g. Syft's php-cli binary classifier)
        supplier = "php"
        up_ver = upstream_part(pkg.ptype, pkg.version)
        if ub.remediation == "release" and ub.fixed_version and up_ver:
            c = compare("generic", up_ver, ub.fixed_version)
            fix_status = "unknown" if c is None else ("fixed" if c >= 0 else "vulnerable")
            supplier_rem = "release"
        elif up_ver and ub.provenance in AFFECTED_PROVENANCE:
            fix_status, supplier_rem = "vulnerable", ub.remediation
        k10 = "explicit" if ub.remediation == "release" else "silent"
    else:
        advs = _advisories(snap, ctx, pkg, branch, event, ctx.families)
        if advs:
            k10 = "explicit"
        per_cve = [a for a in advs if a.cve in event.cves]
        event_level = [a for a in advs if a.cve == event.name]
        for a in event_level:
            ev.append(Evidence("K3", f"{a.family} {a.distro} {a.package}: {a.status}"
                               + (f" in {a.fixed_version}" if a.fixed_version else ""), a.source_url, a.advisory))
        # fixed if the installed version reaches any supplier's fixed version for this scope
        for a in event_level:
            if a.fixed_version and pkg.version:
                c = compare(pkg.ptype, pkg.version, a.fixed_version)
                if c is None:
                    notes.append(f"version not comparable: {pkg.version} vs {a.fixed_version}")
                    continue
                if c >= 0:
                    fix_status, fixed_by = "fixed", a.family
                    break
        if fix_status != "fixed":
            stated = {a.status for a in event_level}
            if stated & {"fixed", "affected", "pending", "no_fix"}:
                fix_status = "vulnerable"
            elif per_cve and all(a.status == "not_affected" for a in per_cve) and len(per_cve) >= len(event.cves):
                fix_status = "not_affected"
            for a in per_cve:
                ev.append(Evidence("K6", f"{a.family} {a.distro}: {a.cve} {a.status}", a.source_url, a.advisory))
        no_fix_stated = any(a.status == "no_fix" and a.family == supplier for a in event_level)
        if fixed_by:
            supplier, supplier_rem = fixed_by, "release"
        elif any(a.status in ("fixed",) and a.family == supplier for a in event_level):
            supplier_rem = "release"
        elif any(a.status == "pending" for a in event_level):
            supplier_rem = "planned"
        elif no_fix_stated:
            supplier_rem = "none"

        # ---- commitment (K4): pending fix, a fix for this scope, or a usable lifecycle tier
        if not no_fix_stated:
            for a in event_level:
                if a.family == supplier and a.status in ("fixed", "pending"):
                    committed_by = a.family
                    break
            if committed_by is None:
                for t in snap.lifecycle:
                    if t.family in ctx.families and t.distro == (ctx.distro or "") and t.end_of_security_support \
                            and t.end_of_security_support > t0 and _tier_usable(t, pkg, opts.entitlements, fixed_by):
                        committed_by = t.family
                        ev.append(Evidence("K4", f"{t.family} {t.distro} {t.tier} support until "
                                           f"{t.end_of_security_support} ({t.access})", t.source_url))
                        break

    # ---- class (Algorithm 1)
    exp_cls = up_cls
    if up_cls in ("E2", "E3"):
        if fix_status == "fixed":
            exp_cls = "D+"
        elif committed_by:
            exp_cls = "D~"
    attributable = exp_cls in ("E2", "E3") and k5
    # remediable: a fix has reached this build or will reach it through its own supply path
    remediable = fix_status == "fixed" or (exp_cls in REMEDIABLE_CLASSES and not no_fix_stated)
    if no_fix_stated and up_cls in ("E0", "E1"):
        notes.append("Upstream still supports this branch, but the build's supplier states it will not fix it: "
                     "the exposure is attributable to the supplier's lifecycle, not upstream's.")

    # ---- criteria vector
    lapse = (t0 - ub.end_of_security_support).days if ub.end_of_security_support and k2 == "lapsed" else None
    left = (ub.end_of_security_support - t0).days if ub.end_of_security_support and k2 != "lapsed" else None
    k4 = ("upstream_build" if supplier == "php" else
          "fixed_by_supplier" if fix_status == "fixed" else
          "committed" if committed_by else
          "no_fix_stated" if no_fix_stated else
          "not_committed" if (ctx.families and _has_supplier_data(snap, ctx)) else "no_supplier_data")
    mr = _mr_level(snap, supplier)
    k9 = ("unresolved" if not pkg.version else
          "version_only" if pkg.ptype == "generic" else "resolved_by_purl")
    criteria = {
        "K1": bool(ub.end_of_life and ub.end_of_life <= t0),
        "K2": k2,
        "K3": {"upstream": ub.remediation, "supplier": supplier_rem},
        "K4": k4,
        "K5": k5,
        "K6": ub.provenance,
        "K7": {"lapse_days": lapse, "eossec_days_left": left,
               "residual": "bounded" if exp_cls in REMEDIABLE_CLASSES else "unbounded"},
        "K8": mr,
        "K9": k9,
        "K10": k10,
        "K11": len({e.source_url for e in ev if e.source_url}),
        "K13": (any(c in opts.exploited_cves for c in event.cves) if opts.exploited_cves else "not_checked"),
        "horizon_days": event.horizon_days,
    }
    if pkg.ptype == "generic" and supplier == "php":
        notes.append("Identity from an upstream version string only: a distro or vendor build copied into "
                     "this image cannot be told apart (K9).")
    return Verdict(pkg, event.name, exp_cls, up_cls, attributable, fix_status, remediable,
                   supplier, branch, criteria, ev, _actions(exp_cls, fix_status, ub, snap, ctx, t0), notes)


def _has_supplier_data(snap: Snapshot, ctx: SupplierContext) -> bool:
    return any(a.family in ctx.families and a.distro == (ctx.distro or "") for a in snap.advisories) or \
        any(t.family in ctx.families and t.distro == (ctx.distro or "") for t in snap.lifecycle)


def _mr_level(snap: Snapshot, family: str) -> str:
    if family == "php":
        return "html_table+active_json"
    if snap.fix_status_machine_readable(family) and snap.lifecycle_machine_readable(family):
        return "vendor_json"
    if snap.fix_status_machine_readable(family):
        return "vendor_json_fix_only"
    return "html_derived"


def _actions(cls: str, fix: str, ub: UpstreamBranch, snap: Snapshot, ctx: SupplierContext, t0: date) -> List[str]:
    out = []
    if fix == "vulnerable" and cls in ("E0", "E1", "D~"):
        out.append("Patch now: a fixed build is available from your supplier or upstream.")
    if cls == "E1":
        out.append(f"Plan migration: PHP {ub.branch} security support ends {ub.end_of_security_support}.")
    elif cls == "E2":
        out.append("No installable fix from your supply path: build the upstream source patch, migrate to a "
                   "supported branch, or obtain extended support.")
    elif cls == "E3":
        out.append("No fix will be published for this build: migrate, isolate, or obtain extended support.")
    elif cls == "D+":
        out.append("Fixed by your supplier; keep receiving its updates and track its support end date.")
    elif cls == "D~":
        out.append("Your supplier is committed to a fix that has not shipped yet; apply it when released.")
    elif cls == "EX":
        out.append("Affectedness of this branch is not established; verify before acting.")
    if cls in ("E2", "E3"):
        for t in snap.lifecycle:
            if t.family in ctx.families and t.distro == (ctx.distro or "") and t.access == "subscription" \
                    and t.end_of_security_support and t.end_of_security_support > t0:
                out.append(f"Extended support available: {t.family} {t.tier} until {t.end_of_security_support} "
                           "(subscription).")
    return out
