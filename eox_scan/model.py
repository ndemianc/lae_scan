"""Data model shared by the engine, runners, baselines and writers."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Package:
    """One installed package as a scanner sees it."""

    ref: str                        # stable id within the SBOM (bom-ref / Syft id / build id)
    name: str
    version: Optional[str]          # full package version, e.g. 8.0.30-8.el9_8.1; None if unknown
    purl: str                       # full purl including qualifiers
    ptype: str                      # purl type: deb, rpm, apk, generic, ...
    namespace: Optional[str] = None
    distro: Optional[str] = None    # purl distro= qualifier, normalized (e.g. rhel-9, debian-12)
    vendor: Optional[str] = None    # RPM Vendor or equivalent package metadata
    source_name: Optional[str] = None   # source package (dpkg Source, rpm source RPM name, apk origin)
    branch_hint: Optional[str] = None   # upstream branch hint when the version is unknown


@dataclass(frozen=True)
class Event:
    """A vulnerability event (one or more CVEs disclosed and fixed together)."""

    name: str                       # e.g. PHP2Shell
    cves: tuple
    t0: datetime
    horizon_days: int = 90

    @staticmethod
    def parse_t0(s: str) -> datetime:
        s = s.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class Evidence:
    criterion: str
    statement: str
    source_url: str = ""
    document: str = ""


@dataclass
class Verdict:
    package: Package
    event: str
    exposure_class: str                  # E0, E1, E2, E3, EX, D+, D~
    upstream_class: str             # class from upstream data alone (no supplier scope)
    lifecycle_attributable: bool
    fix_status: str                 # fixed | vulnerable | not_affected | unknown
    remediable: bool
    supplier: str                   # supplier family of record, or 'unknown'
    upstream_branch: Optional[str]
    criteria: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Evidence] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    baseline: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": {
                "ref": self.package.ref, "name": self.package.name, "version": self.package.version,
                "purl": self.package.purl, "supplier": self.supplier, "upstream_branch": self.upstream_branch,
            },
            "event": self.event,
            "baseline": self.baseline,
            "exposure": {
                "class": self.exposure_class,
                "upstream_class": self.upstream_class,
                "lifecycle_attributable": self.lifecycle_attributable,
                "fix_status": self.fix_status,
                "remediable": self.remediable,
                "criteria": self.criteria,
                "evidence": [e.__dict__ for e in self.evidence],
                "actions": self.actions,
                "notes": self.notes,
            },
        }
