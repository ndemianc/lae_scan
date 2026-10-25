"""Frozen data snapshot: upstream lifecycle, supplier lifecycle tiers, supplier
advisories and feed metadata. Loads from the CSV source directory or from the
built eox.db; both give the same in-memory Snapshot."""
from __future__ import annotations

import csv
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

# family -> display name used in supplier_feeds.csv
FEED_NAME = {
    "php": "PHP Group (upstream)", "debian": "Debian", "freexian-elts": "Freexian (Debian ELTS)",
    "ubuntu": "Canonical (Ubuntu)", "redhat": "Red Hat", "suse": "SUSE", "opensuse": "SUSE (openSUSE)",
    "alpine": "Alpine Linux", "docker-official": "Docker Official Images", "getpagespeed": "GetPageSpeed",
    "remi": "Remi Collet (remirepo)",
}

CSV_FILES = {
    "upstream": "upstream_php_branches.csv",
    "lifecycle": "supplier_lifecycle.csv",
    "advisories": "supplier_advisories.csv",
    "feeds": "supplier_feeds.csv",
}


def _d(s: Optional[str]) -> Optional[date]:
    s = (s or "").strip()
    if not s or s == "tba":
        return None
    return date.fromisoformat(s[:10])


@dataclass(frozen=True)
class UpstreamBranch:
    branch: str
    general_availability: Optional[date]
    end_of_active_support: Optional[date]
    end_of_security_support: Optional[date]
    end_of_life: Optional[date]
    last_release: str
    remediation: str            # release | source | none
    fixed_version: str
    provenance: str             # confirmed | reported | conflicting | unconfirmed | unknown
    provenance_basis: str
    source_url: str


@dataclass(frozen=True)
class LifecycleTier:
    family: str
    distro: str
    tier: str
    end_of_security_support: Optional[date]
    access: str                 # public | subscription
    mr_level: str
    source_url: str


@dataclass(frozen=True)
class Advisory:
    cve: str
    family: str
    distro: str
    package: str
    upstream_branch: str
    fixed_version: str
    status: str                 # fixed | pending | affected | no_fix | not_affected | under_investigation
    advisory: str
    source_url: str
    retrieved: str


@dataclass
class Snapshot:
    as_of: str
    upstream: Dict[str, UpstreamBranch]
    lifecycle: List[LifecycleTier]
    advisories: List[Advisory]
    feeds: Dict[str, Dict[str, str]] = field(default_factory=dict)

    # ---------------------------------------------------------------- loaders
    @classmethod
    def from_csv_dir(cls, path: str) -> "Snapshot":
        def rows(key):
            with open(os.path.join(path, CSV_FILES[key]), newline="") as f:
                return list(csv.DictReader(f))
        return cls._from_rows(os.path.basename(os.path.normpath(path)).replace("snapshot-", ""),
                              rows("upstream"), rows("lifecycle"), rows("advisories"), rows("feeds"))

    @classmethod
    def from_db(cls, db_path: str) -> "Snapshot":
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row

        def rows(table):
            return [dict(r) for r in con.execute(f"SELECT * FROM {table}")]
        meta = {r["key"]: r["value"] for r in rows("meta")}
        snap = cls._from_rows(meta.get("as_of", ""), rows("upstream_branches"), rows("supplier_lifecycle"),
                              rows("advisory_status"), rows("supplier_feeds"))
        con.close()
        return snap

    @classmethod
    def load(cls, path: str) -> "Snapshot":
        """Accept a CSV source dir, a built snapshot dir (with eox.db) or a eox.db file."""
        if os.path.isfile(path):
            return cls.from_db(path)
        if os.path.isfile(os.path.join(path, "eox.db")):
            return cls.from_db(os.path.join(path, "eox.db"))
        return cls.from_csv_dir(path)

    @classmethod
    def _from_rows(cls, as_of, up, lc, adv, feeds) -> "Snapshot":
        upstream = {}
        for r in up:
            upstream[r["branch"]] = UpstreamBranch(
                branch=r["branch"], general_availability=_d(r.get("general_availability")),
                end_of_active_support=_d(r.get("end_of_active_support")),
                end_of_security_support=_d(r.get("end_of_security_support")), end_of_life=_d(r.get("end_of_life")),
                last_release=r.get("last_release", ""), remediation=r.get("upstream_fix", r.get("remediation", "none")),
                fixed_version=r.get("fixed_version") or "", provenance=r.get("provenance", "unknown"),
                provenance_basis=r.get("provenance_basis", ""), source_url=r.get("source", r.get("source_url", "")))
        lifecycle = [LifecycleTier(r["family"], r["distro"], r["tier"], _d(r["end_of_security_support"]),
                                   r["access"], r["mr_level"], r["source_url"]) for r in lc]
        advisories = [Advisory(r["cve"], r["family"], r["distro"] or "", r["package"], r["upstream_branch"] or "",
                               r["fixed_version"] or "", r["status"], r.get("advisory") or "", r["source_url"],
                               r.get("retrieved", "")) for r in adv]
        feed_map = {r["vendor"]: r for r in feeds}
        return cls(as_of=as_of, upstream=upstream, lifecycle=lifecycle, advisories=advisories, feeds=feed_map)

    # ------------------------------------------------------------ feed facts
    def feed(self, family: str) -> Dict[str, str]:
        return self.feeds.get(FEED_NAME.get(family, family), {})

    def fix_status_machine_readable(self, family: str) -> bool:
        return self.feed(family).get("fix_status_mr") == "yes"

    def lifecycle_machine_readable(self, family: str) -> bool:
        return self.feed(family).get("lifecycle_mr") == "yes"

    def restricted_to_machine_readable(self) -> "Snapshot":
        """Only the supplier data that is machine-readable today (the paper's F_today)."""
        return Snapshot(
            as_of=self.as_of, upstream=self.upstream,
            lifecycle=[t for t in self.lifecycle if self.lifecycle_machine_readable(t.family)],
            advisories=[a for a in self.advisories if self.fix_status_machine_readable(a.family)],
            feeds=self.feeds)
