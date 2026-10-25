"""Read Syft JSON and CycloneDX JSON into Packages; write minimal CycloneDX."""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from .model import Package
from .supplier import normalize_distro, package_from_purl

PROP_PREFIX = "eox:"


def read(path: str) -> List[Package]:
    with open(path) as f:
        doc = json.load(f)
    if doc.get("bomFormat") == "CycloneDX":
        return read_cyclonedx(doc)
    if "artifacts" in doc:
        return read_syft(doc)
    raise ValueError(f"{path}: neither CycloneDX JSON nor Syft JSON")


def read_cyclonedx(doc: Dict) -> List[Package]:
    out = []
    for c in doc.get("components", []):
        purl = c.get("purl")
        if not purl:
            continue
        props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
        vendor = (c.get("supplier") or {}).get("name") or props.get(PROP_PREFIX + "vendor")
        out.append(package_from_purl(purl, ref=c.get("bom-ref", purl), vendor=vendor,
                                     source_name=props.get(PROP_PREFIX + "source_name") or props.get("syft:metadata:source"),
                                     branch_hint=props.get(PROP_PREFIX + "upstream_branch")))
    return out


def read_syft(doc: Dict) -> List[Package]:
    distro = doc.get("distro") or {}
    distro_q = f"{distro.get('id')}-{distro.get('versionID')}" if distro.get("id") else None
    out = []
    for a in doc.get("artifacts", []):
        purl = a.get("purl")
        if not purl:
            continue
        md = a.get("metadata") or {}
        source = md.get("source") or md.get("originPackage")
        srpm = md.get("sourceRpm")
        if not source and srpm:
            source = srpm.rsplit("-", 2)[0]
        pkg = package_from_purl(purl, ref=a.get("id", purl), vendor=md.get("vendor"), source_name=source)
        if pkg.distro is None and distro_q and pkg.ptype in ("deb", "rpm", "apk"):
            pkg = Package(**{**pkg.__dict__, "distro": normalize_distro(pkg.ptype, distro_q)})
        out.append(pkg)
    return out


def write_cyclonedx(path: str, components: List[Dict], serial: Optional[str] = None) -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}
    if serial:
        doc["serialNumber"] = serial
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
