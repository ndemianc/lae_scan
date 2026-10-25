#!/usr/bin/env python3
"""Derive data/snapshot-2026-10-22/supplier_advisories.csv from the paper's
build records (replay/builds.csv).

Each record with a supplier-stated status becomes one advisory row keyed by
(family, distro, package, upstream branch). Records whose status was derived
from version equality ("[derived]") are skipped, so the snapshot never encodes
the version-comparison logic it is used to evaluate.
"""
import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from paper_build_map import BUILD_MAP  # noqa: E402

ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "replay", "builds.csv")
DST = os.path.join(ROOT, "data", "snapshot-2026-10-22", "supplier_advisories.csv")

FAMILY = {
    "Debian": "debian", "Freexian (Debian ELTS)": "freexian-elts", "Canonical (Ubuntu)": "ubuntu",
    "Red Hat": "redhat", "SUSE": "suse", "SUSE (openSUSE)": "opensuse", "Alpine Linux": "alpine",
    "GetPageSpeed": "getpagespeed", "Remi Collet (remirepo)": "remi",
}
ADV = re.compile(r"(DSA-\d+-\d+|DLA-\d+-\d+|ELA-\d+-\d+|USN-\d+-\d+|RHSA-\d{4}:\d+|SUSE-SU-\d{4}:\d+-\d+|"
                 r"openSUSE-Tumbleweed-\d{4}-\d+)")

# Status for rows whose supplier states "vulnerable" without a fixed version
EXTRA = {
    # Debian testing: fixed in unstable 8.4.27-1, migration to forky pending (tracker)
    "B014": ("affected", "8.4.27-1"),
    # Debian unstable php8.2: tracker lists (unfixed)
    "B016": ("affected", ""),
    # Remi EL7 repositories: reported vulnerable, no patched build published
    "B078": ("no_fix", ""), "B079": ("no_fix", ""), "B080": ("no_fix", ""),
    # Red Hat RHEL 9 php:8.4 stream: fix_state "Affected" (fix planned)
    "B034": ("pending", ""),
}

# RHEL 7 ships PHP 5.4 and RHEL 6 ships PHP 5.3; the tracker rows carry no version
RHEL_LEGACY_BRANCH = {"B037": "5.4", "B038": "5.4", "B039": "5.3", "B040": "5.3"}

rows = []
with open(SRC, newline="") as f:
    for b in csv.DictReader(f):
        bid = b["build_id"]
        fam = FAMILY.get(b["vendor"])
        if fam is None or bid not in BUILD_MAP or "[derived]" in b["status_detail"]:
            continue
        _, _, name, distro, _, _ = BUILD_MAP[bid]
        m = ADV.search(b["status_detail"])
        base = dict(family=fam, distro=distro or "", package=name, upstream_branch=b["upstream_branch"],
                    advisory=m.group(1) if m else "", source_url=b["source_url"], retrieved=b["retrieved"])
        if bid in RHEL_LEGACY_BRANCH:
            base["upstream_branch"] = RHEL_LEGACY_BRANCH[bid]
        if b["cve_scope"] != "both":
            cve = "CVE-2026-" + b["cve_scope"]
            status = {"not_affected": "not_affected", "unknown": "under_investigation"}.get(b["fix_status"], b["fix_status"])
            rows.append(dict(cve=cve, fixed_version="", status=status, **base))
            continue
        if b["fix_status"] == "fixed" and b["package_version"]:
            rows.append(dict(cve="PHP2Shell", fixed_version=b["package_version"], status="fixed", **base))
        elif bid in EXTRA:
            st, fv = EXTRA[bid]
            rows.append(dict(cve="PHP2Shell", fixed_version=fv, status=st, **base))

cols = ["cve", "family", "distro", "package", "upstream_branch", "fixed_version", "status", "advisory", "source_url", "retrieved"]
with open(DST, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)
print(f"wrote {len(rows)} advisory rows to {os.path.relpath(DST, ROOT)}")
