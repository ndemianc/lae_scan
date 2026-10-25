"""Supplier resolution (criterion K4) from the full purl and package metadata.

xeol's ShortPurl cuts the purl at '@', so the distro qualifier is lost before
lookup. eox-scan keeps the whole purl and resolves which supplier families may
speak for the build: the distro family from namespace + distro, overridden by
the RPM vendor when a third party (Remi, GetPageSpeed) built the package.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from packageurl import PackageURL

from .model import Package
from .versions import branch_of, upstream_part

# (purl type, namespace) -> supplier families that publish statements for that namespace
NAMESPACE_FAMILIES = {
    ("deb", "debian"): ["debian", "freexian-elts"],
    ("deb", "ubuntu"): ["ubuntu"],
    ("rpm", "redhat"): ["redhat"],
    ("rpm", "rhel"): ["redhat"],
    ("rpm", "suse"): ["suse"],
    ("rpm", "sles"): ["suse"],
    ("rpm", "opensuse"): ["opensuse"],
    ("rpm", "centos"): ["centos"],
    ("apk", "alpine"): ["alpine"],
    ("generic", None): ["php"],
}

# RPM Vendor substrings -> supplier family (third-party builders override the namespace)
VENDOR_FAMILIES = [
    ("getpagespeed", "getpagespeed"),
    ("remi", "remi"),
    ("red hat", "redhat"),
    ("opensuse", "opensuse"),
    ("suse", "suse"),
    ("centos", "centos"),
]

PHP_NAME = re.compile(r"^(php|php-main|php-cli|php-fpm|php-cgi|libphp|libapache2-mod-php|"
                      r"php\d+(\.\d+)?|php\d+-php|php\d+(\.\d+)?-(cli|fpm|cgi|common)|"
                      r"libapache2-mod-php\d+(\.\d+)?)$")
_NAME_BRANCH = re.compile(r"php(\d)\.?(\d)")


@dataclass(frozen=True)
class SupplierContext:
    families: List[str]
    distro: Optional[str]
    by_vendor: bool


def normalize_distro(ptype: str, distro: Optional[str]) -> Optional[str]:
    """Normalize Syft's distro qualifier to the snapshot's scope keys."""
    if not distro:
        return None
    d = distro.lower()
    for prefix in ("rhel-", "centos-", "rocky-", "almalinux-"):
        if d.startswith(prefix):
            return prefix + d[len(prefix):].split(".")[0]
    m = re.match(r"^alpine-(\d+\.\d+)", d)
    if m:
        return f"alpine-{m.group(1)}"
    m = re.match(r"^debian-(\d+)", d)
    if m:
        return f"debian-{m.group(1)}"
    return d


def package_from_purl(purl: str, ref: str = "", vendor: Optional[str] = None,
                      source_name: Optional[str] = None, branch_hint: Optional[str] = None) -> Package:
    p = PackageURL.from_string(purl)
    q = p.qualifiers or {}
    if not source_name and q.get("upstream"):
        # Syft writes the source package as a qualifier: upstream=php7.4 or upstream=php7.4@7.4.33-1
        source_name = q["upstream"].split("@")[0]
    return Package(ref=ref or purl, name=p.name, version=p.version, purl=purl, ptype=p.type,
                   namespace=p.namespace, distro=normalize_distro(p.type, q.get("distro")),
                   vendor=vendor, source_name=source_name, branch_hint=branch_hint)


DEB_METAPACKAGES = {"php", "php-cli", "php-fpm", "php-cgi", "php-common", "libapache2-mod-php"}


def is_php(pkg: Package) -> bool:
    # Debian/Ubuntu php-defaults metapackages (e.g. php 2:8.2+93) only depend on a phpX.Y package
    if pkg.ptype == "deb" and (pkg.name in DEB_METAPACKAGES or pkg.source_name == "php-defaults"):
        return False
    return bool(PHP_NAME.match(pkg.name)) or bool(pkg.source_name and PHP_NAME.match(pkg.source_name))


def resolve(pkg: Package) -> SupplierContext:
    if pkg.vendor:
        v = pkg.vendor.lower()
        for needle, fam in VENDOR_FAMILIES:
            if needle in v:
                return SupplierContext([fam], pkg.distro, True)
    fams = NAMESPACE_FAMILIES.get((pkg.ptype, pkg.namespace)) or NAMESPACE_FAMILIES.get((pkg.ptype, None)) or []
    return SupplierContext(list(fams), pkg.distro, False)


def upstream_branch(pkg: Package) -> Optional[str]:
    """Upstream PHP branch from the version, else the package name (php8.2, php74), else a hint."""
    b = branch_of(upstream_part(pkg.ptype, pkg.version))
    if b:
        return b
    for name in (pkg.name, pkg.source_name or ""):
        m = _NAME_BRANCH.search(name)
        if m:
            return f"{m.group(1)}.{m.group(2)}"
    return pkg.branch_hint
