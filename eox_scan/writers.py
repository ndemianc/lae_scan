"""Output writers: json (full criteria and evidence), CSAF 2.0 VEX, and a text table."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List

from .model import Event, Verdict

TOOL = "eox-scan"

_CSAF_REMEDIATION = {
    "E0": ("vendor_fix", "A fixed build is available from the supplier or upstream. Update."),
    "E1": ("vendor_fix", "A fixed build is available; upstream security support for this branch ends soon. "
                         "Update and plan migration."),
    "D~": ("vendor_fix", "The supplier has committed to a fix that has not shipped yet. Apply it when released."),
    "E2": ("none_available", "Upstream support has ended and only a source patch exists. Build the patch, migrate "
                             "to a supported branch, or obtain extended support."),
    "E3": ("no_fix_planned", "Upstream support has ended and no fix will be published. Migrate, isolate, or "
                             "obtain extended support."),
    "EX": ("none_available", "Affectedness of this branch is not established. Verify before acting."),
}


def report_json(verdicts: List[Verdict], event: Event, snapshot_as_of: str, meta: Dict = None) -> Dict:
    classes: Dict[str, int] = {}
    for v in verdicts:
        classes[v.exposure_class] = classes.get(v.exposure_class, 0) + 1
    return {
        "tool": TOOL,
        "event": {"name": event.name, "cves": list(event.cves), "t0": event.t0.isoformat(),
                  "horizon_days": event.horizon_days},
        "snapshot": snapshot_as_of,
        "summary": {"packages": len(verdicts), "classes": dict(sorted(classes.items())),
                    "lifecycle_attributable": sum(v.lifecycle_attributable for v in verdicts)},
        **(meta or {}),
        "results": [v.to_dict() for v in verdicts],
    }


def csaf_vex(verdicts: List[Verdict], event: Event, publisher: str = "eox-scan user",
             namespace: str = "https://example.invalid", now: datetime = None) -> Dict:
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat()
    products, pid_of = [], {}
    for v in verdicts:
        if v.package.purl in pid_of:
            continue
        pid = "P" + hashlib.sha256(v.package.purl.encode()).hexdigest()[:10]
        pid_of[v.package.purl] = pid
        products.append({"product_id": pid, "name": f"{v.package.name} {v.package.version or ''}".strip(),
                         "product_identification_helper": {"purl": v.package.purl}})
    status = {"fixed": [], "known_affected": [], "known_not_affected": [], "under_investigation": []}
    remediations: Dict[str, Dict] = {}
    notes = []
    for v in verdicts:
        pid = pid_of[v.package.purl]
        if v.fix_status == "fixed":
            bucket = "fixed"
        elif v.fix_status == "not_affected":
            bucket = "known_not_affected"
        elif v.fix_status == "vulnerable" or (v.fix_status == "unknown" and v.exposure_class in ("E2", "E3")):
            bucket = "known_affected"
        else:
            bucket = "under_investigation"
        if pid not in status[bucket]:
            status[bucket].append(pid)
        if bucket == "known_affected":
            cat, text = _CSAF_REMEDIATION.get(v.exposure_class, _CSAF_REMEDIATION["EX"])
            r = remediations.setdefault(f"{cat}|{text}", {"category": cat, "details": text, "product_ids": []})
            r["product_ids"].append(pid)
        notes.append(f"{pid}: class {v.exposure_class} (upstream {v.upstream_class}), supplier {v.supplier}, "
                     f"PHP {v.upstream_branch}")
    vulns = []
    for cve in event.cves:
        vul = {"cve": cve, "product_status": {k: sorted(x) for k, x in status.items() if x},
               "notes": [{"category": "details", "title": "Lifecycle-attributable exposure",
                          "text": "\n".join(notes)}]}
        if remediations:
            vul["remediations"] = [{**r, "product_ids": sorted(r["product_ids"])} for r in remediations.values()]
        if status["known_not_affected"]:
            vul["threats"] = [{"category": "impact", "details": "The supplier states this build is not affected.",
                               "product_ids": sorted(status["known_not_affected"])}]
        vulns.append(vul)
    digest = hashlib.sha256(json.dumps([v.to_dict() for v in verdicts], sort_keys=True,
                                       default=str).encode()).hexdigest()[:16]
    return {
        "document": {
            "category": "csaf_vex", "csaf_version": "2.0",
            "publisher": {"category": "user", "name": publisher, "namespace": namespace},
            "title": f"{event.name}: lifecycle-attributable exposure assessment",
            "tracking": {"id": f"eox-{event.name.lower()}-{digest}", "status": "final", "version": "1",
                         "initial_release_date": now, "current_release_date": now,
                         "revision_history": [{"date": now, "number": "1", "summary": "Generated by eox-scan."}],
                         "generator": {"engine": {"name": TOOL}}},
        },
        "product_tree": {"full_product_names": products},
        "vulnerabilities": vulns,
    }


def table(verdicts: List[Verdict]) -> str:
    with_base = any(v.baseline for v in verdicts)
    head = ("PACKAGE", "VERSION", "SUPPLIER", "PHP", "CLASS", "FIX", "REMEDIABLE", "ATTRIBUTABLE")
    rows = [head + (("B1 FIX", "B2 REMEDIABLE", "XEOL") if with_base else ())]
    yn = {True: "yes", False: "no", None: "-"}
    for v in verdicts:
        r = (v.package.name, v.package.version or "-", v.supplier, v.upstream_branch or "-", v.exposure_class,
             v.fix_status, yn[v.remediable], yn[v.lifecycle_attributable])
        if with_base:
            b = v.baseline or {}
            fixed = (b.get("B1") or {}).get("fixed")
            r += ("fixed" if fixed else "vulnerable" if fixed is False else "-", yn[b.get("B2_remediable")],
                  (b.get("xeol") or {}).get("verdict", "-"))
        rows.append(r)
    w = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in rows)
