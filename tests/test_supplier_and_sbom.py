import os

from conftest import FIXTURES, ROOT

from eox_scan import sbom
from eox_scan.supplier import is_php, normalize_distro, package_from_purl, resolve, upstream_branch


def test_namespace_and_vendor_resolution():
    deb = package_from_purl("pkg:deb/debian/php7.4@7.4.33-1%2Bdeb11u14?distro=debian-11")
    assert resolve(deb).families == ["debian", "freexian-elts"]
    remi = package_from_purl("pkg:rpm/centos/php@8.0.30-6.el7.remi?distro=centos-7",
                             vendor="Remi's RPM repository <https://rpms.remirepo.net/>")
    ctx = resolve(remi)
    assert ctx.families == ["remi"] and ctx.by_vendor and ctx.distro == "centos-7"
    assert resolve(package_from_purl("pkg:generic/php-cli@8.1.2")).families == ["php"]


def test_distro_normalization():
    assert normalize_distro("rpm", "rhel-9.4") == "rhel-9"
    assert normalize_distro("apk", "alpine-3.24.1") == "alpine-3.24"
    assert normalize_distro("deb", "debian-12.7") == "debian-12"
    assert normalize_distro("deb", "ubuntu-22.04") == "ubuntu-22.04"


def test_branch_from_name_when_version_missing():
    assert upstream_branch(package_from_purl("pkg:deb/debian/php8.2?distro=debian-sid")) == "8.2"
    assert upstream_branch(package_from_purl("pkg:rpm/suse/php74@7.4.33-1.74.1")) == "7.4"
    assert upstream_branch(package_from_purl("pkg:rpm/centos/php?distro=centos-7", branch_hint="8.1")) == "8.1"


def test_syft_json_reader():
    pkgs = sbom.read(os.path.join(FIXTURES, "syft_debian11.json"))
    by = {p.ref: p for p in pkgs}
    assert by["a1"].source_name == "php7.4" and by["a1"].distro == "debian-11"
    assert is_php(by["a1"]) and is_php(by["a5"])
    assert not is_php(by["a3"]), "php-defaults metapackage is not a PHP build"
    assert not is_php(by["a4"])
    rpm = sbom.read(os.path.join(FIXTURES, "syft_centos7_remi.json"))
    assert rpm[0].vendor.startswith("Remi") and rpm[0].source_name == "php"


def test_cyclonedx_reader_keeps_branch_hint():
    pkgs = {p.ref: p for p in sbom.read(os.path.join(ROOT, "replay", "php2shell.cdx.json"))}
    assert pkgs["B079"].version is None and pkgs["B079"].branch_hint == "7.4"
    assert pkgs["B031"].vendor == "Red Hat, Inc."
