"""Baselines from the paper.

B1  version-string scanner: compares the upstream version with the upstream
    fixed release of its branch; remediable iff upstream ships a release fix.
B2  upstream-lifecycle-aware scanner: remediable iff the upstream branch's
    End-of-Security-Support lies after T0. In eox-scan, B2 is the unmodified
    xeol binary (runners.xeol) or, when it is not installed, a faithful
    emulation of xeol's matcher (baseline.xeol_emulation).
"""
from __future__ import annotations

from typing import Dict, Optional

from ..model import Event, Package
from ..snapshot import Snapshot
from ..supplier import upstream_branch
from ..versions import compare, upstream_part


def b1(pkg: Package, snap: Snapshot) -> Dict[str, Optional[bool]]:
    branch = upstream_branch(pkg)
    ub = snap.upstream.get(branch) if branch else None
    has_release = bool(ub and ub.remediation == "release" and ub.fixed_version)
    fixed = None
    up = upstream_part(pkg.ptype, pkg.version)
    if up is not None:
        if has_release:
            c = compare("generic", up, ub.fixed_version)
            fixed = None if c is None else c >= 0
        else:
            fixed = False
    return {"fixed": fixed, "remediable": has_release}


def b2_remediable(pkg: Package, snap: Snapshot, event: Event) -> Optional[bool]:
    branch = upstream_branch(pkg)
    ub = snap.upstream.get(branch) if branch else None
    if ub is None or ub.end_of_security_support is None:
        return None
    return ub.end_of_security_support > event.t0.date()
