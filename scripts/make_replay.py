#!/usr/bin/env python3
"""Turn the paper's build records (replay/builds.csv) into scanner inputs.

Writes:
  replay/php2shell.cdx.json   one CycloneDX component per build, bom-ref = build id
  replay/ground_truth.csv     labels for scoring (from the build records only)

Every label comes from builds.csv; the SBOM carries only what a scanner sees
(purl, RPM vendor, distro qualifier). Builds without a package version keep a
version-less purl and an eox:upstream_branch property, as an SBOM produced from
a package manifest without installed versions would.
"""
from __future__ import annotations

import csv
import os
import sys

from packageurl import PackageURL

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from paper_build_map import BUILD_MAP  # noqa: E402
from eox_scan.sbom import write_cyclonedx  # noqa: E402

EXCLUDED_ROWS = ("B005", "B006", "B007", "B008", "B009")   # branch-level rows and a pre-release


def truth_fixed(b):
    s = b["fix_status"].strip()
    return "true" if s == "fixed" else "false" if s in ("vulnerable", "pending", "will_not_fix") else ""


def truth_remediable(b):
    s, sup = b["fix_status"].strip(), b["vendor_supports_branch"].strip()
    if s == "fixed":
        return "true"
    if s == "will_not_fix":
        return "false"
    if s in ("vulnerable", "pending"):
        return {"yes": "true", "no": "false"}.get(sup, "")
    return ""


def main(builds_csv=os.path.join(ROOT, "replay", "builds.csv"), out_dir=os.path.join(ROOT, "replay")):
    with open(builds_csv, newline="") as f:
        builds = list(csv.DictReader(f))
    comps, truth = [], []
    for b in builds:
        bid = b["build_id"]
        derived = "[derived]" in b["status_detail"]
        truth.append({
            "build_id": bid, "vendor": b["vendor"], "upstream_branch": b["upstream_branch"].strip(),
            "upstream_version_string": b["upstream_version_string"].strip(), "cve_scope": b["cve_scope"].strip(),
            "fix_status": b["fix_status"].strip(), "vendor_supports_branch": b["vendor_supports_branch"].strip(),
            "truth_fixed": truth_fixed(b), "truth_remediable": truth_remediable(b),
            "derived": "true" if derived else "false",
            "eligible": "true" if (bid not in EXCLUDED_ROWS and b["cve_scope"].strip() == "both") else "false",
        })
        if bid not in BUILD_MAP:
            continue
        ptype, ns, name, distro, _family, vendor = BUILD_MAP[bid]
        version = b["package_version"].strip() or None
        quals = {"distro": distro} if distro else {}
        purl = PackageURL(type=ptype, namespace=ns, name=name, version=version, qualifiers=quals).to_string()
        c = {"type": "application" if ptype == "generic" else "library", "bom-ref": bid, "name": name,
             "purl": purl, "properties": [{"name": "eox:replay_vendor", "value": b["vendor"]}]}
        if version:
            c["version"] = version
        else:
            c["properties"].append({"name": "eox:upstream_branch", "value": b["upstream_branch"].strip()})
        if vendor:
            c["supplier"] = {"name": vendor}
        if ptype == "deb":
            c["properties"].append({"name": "eox:source_name", "value": name})
        comps.append(c)
    os.makedirs(out_dir, exist_ok=True)
    write_cyclonedx(os.path.join(out_dir, "php2shell.cdx.json"), comps,
                    serial="urn:uuid:5b1f5f4e-2b0c-4c1e-9a52-0d1c2a3e4f50")
    with open(os.path.join(out_dir, "ground_truth.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(truth[0].keys()))
        w.writeheader()
        w.writerows(truth)
    print(f"{len(comps)} components, {len(truth)} truth rows -> {out_dir}")


if __name__ == "__main__":
    main()
