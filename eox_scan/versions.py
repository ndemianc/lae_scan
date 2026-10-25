"""Ecosystem-aware version handling.

xeol (Masterminds semver v1) cannot parse RPM release strings with '_' or
Debian/Ubuntu versions with a second '+', and silently drops those packages.
eox-scan compares OS package versions with `univers`, and reports a parse
failure as an explicit `None` (unknown) instead of a missing match.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

from univers.versions import AlpineLinuxVersion, DebianVersion, RpmVersion

_ECOSYSTEM = {"deb": DebianVersion, "rpm": RpmVersion, "apk": AlpineLinuxVersion}
_NUM = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _generic_key(v: str) -> Optional[Tuple]:
    """Order plain upstream versions such as 8.2.35 or 8.6.0RC4."""
    m = re.match(r"^v?(\d+(?:\.\d+)*)(.*)$", v.strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums)) if len(nums) < 4 else nums
    rest = m.group(2).lower()
    # a pre-release suffix (alpha, beta, RC) sorts before the final release
    pre = 0 if not rest else (-1 if re.match(r"^[-.]?(alpha|beta|rc|a|b)", rest) else 1)
    return nums + (pre, rest)


def compare(ptype: str, a: str, b: str) -> Optional[int]:
    """Return -1, 0 or 1 comparing a with b in ecosystem `ptype`; None if either cannot be parsed."""
    if a is None or b is None:
        return None
    cls = _ECOSYSTEM.get(ptype)
    try:
        if cls is not None:
            va, vb = cls(a), cls(b)
        else:
            va, vb = _generic_key(a), _generic_key(b)
            if va is None or vb is None:
                return None
    except Exception:  # univers raises InvalidVersion and ValueError subclasses
        return None
    return (va > vb) - (va < vb)


def upstream_part(ptype: str, version: Optional[str]) -> Optional[str]:
    """The upstream version inside a package version, e.g. '8.0.30' from '8.0.30-8.el9_8.1'."""
    if not version:
        return None
    v = version.split(":", 1)[1] if re.match(r"^\d+:", version) else version
    if ptype in ("deb", "rpm", "apk") and "-" in v:
        v = v.rsplit("-", 1)[0]
    return v


def branch_of(version: Optional[str]) -> Optional[str]:
    """'8.2' from '8.2.35', '5.5' from '5.5.9+dfsg'."""
    if not version:
        return None
    m = _NUM.match(version)
    if not m or m.group(2) is None:
        return None
    return f"{int(m.group(1))}.{int(m.group(2))}"
