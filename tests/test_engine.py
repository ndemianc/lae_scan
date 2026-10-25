import csv
import os
from datetime import timedelta

import pytest
from conftest import ROOT

from eox_scan import sbom
from eox_scan.engine import EngineOptions, classify, upstream_class
from eox_scan.model import Event
from eox_scan.reference import paper_reference
from eox_scan.supplier import package_from_purl

SBOM = os.path.join(ROOT, "replay", "php2shell.cdx.json")


def _builds():
    with open(os.path.join(ROOT, "replay", "builds.csv"), newline="") as f:
        return {r["build_id"]: r for r in csv.DictReader(f)}


def _branches():
    with open(os.path.join(ROOT, "data", "snapshot-2026-10-22", "upstream_php_branches.csv"), newline="") as f:
        return {r["branch"]: r for r in csv.DictReader(f)}


def test_every_build_matches_the_paper_reference(snap, event):
    """The engine, reading only the SBOM and the snapshot, gives the class the paper's
    reference code gives from the labelled build records."""
    builds, branches = _builds(), _branches()
    mismatches = []
    for p in sbom.read(SBOM):
        want = paper_reference.classify_build(builds[p.ref], branches, 90)
        got = classify(p, snap, event).exposure_class
        if got != want:
            mismatches.append((p.ref, got, want))
    assert not mismatches


@pytest.mark.parametrize("branch,expected", [
    ("8.5", "E0"), ("8.4", "E0"), ("8.3", "E0"), ("8.2", "E1"),
    ("8.1", "E2"), ("8.0", "E2"), ("7.4", "E2"), ("7.3", "E3"), ("7.0", "E3"), ("5.6", "E3"),
    ("5.4", "EX"), ("5.3", "EX"), ("5.1", "EX"),
])
def test_upstream_classes(snap, event, branch, expected):
    assert upstream_class(snap.upstream[branch], event.t0.date(), 90)[0] == expected


def test_horizon_moves_e1(snap, event):
    assert upstream_class(snap.upstream["8.2"], event.t0.date(), 30)[0] == "E0"


def _deb11(version):
    return package_from_purl(f"pkg:deb/debian/php7.4@{version}?distro=debian-11", source_name="php7.4")


def test_debian_lts_ended_without_elts_is_e2(snap, event):
    v = classify(_deb11("7.4.33-1+deb11u10"), snap, event)
    assert (v.exposure_class, v.fix_status, v.remediable, v.lifecycle_attributable) == ("E2", "vulnerable", False, True)
    assert any("freexian-elts" in a and "subscription" in a for a in v.actions)


def test_elts_entitlement_makes_it_committed(snap, event):
    v = classify(_deb11("7.4.33-1+deb11u10"), snap, event, EngineOptions(entitlements={"freexian-elts"}))
    assert v.exposure_class == "D~" and v.remediable and not v.lifecycle_attributable


def test_elts_build_is_fixed_by_freexian(snap, event):
    v = classify(_deb11("7.4.33-1+deb11u14"), snap, event)
    assert (v.exposure_class, v.supplier, v.criteria["K4"]) == ("D+", "freexian-elts", "fixed_by_supplier")


def test_ubuntu_esm_build_counts_as_entitled(snap, event):
    p = package_from_purl("pkg:deb/ubuntu/php7.4@7.4.3-4ubuntu2.29%2Besm5?distro=ubuntu-20.04")
    assert classify(p, snap, event).exposure_class == "D+"


def test_remi_no_fix_on_centos7(snap, event):
    p = package_from_purl("pkg:rpm/centos/php@8.0.30-6.el7.remi?distro=centos-7",
                          vendor="Remi's RPM repository <https://rpms.remirepo.net/>")
    v = classify(p, snap, event)
    assert (v.exposure_class, v.fix_status, v.remediable, v.criteria["K4"]) == ("E2", "vulnerable", False, "no_fix_stated")


def test_rhel_legacy_split_cves_are_ex(snap, event):
    p = package_from_purl("pkg:rpm/redhat/php?distro=rhel-7", vendor="Red Hat, Inc.", branch_hint="5.4")
    v = classify(p, snap, event)
    assert v.exposure_class == "EX" and v.criteria["K6"] == "conflicting"


def test_generic_upstream_build_flags_k9(snap, event):
    v = classify(package_from_purl("pkg:generic/php-cli@8.4.24"), snap, event)
    assert (v.exposure_class, v.fix_status, v.criteria["K9"]) == ("E0", "vulnerable", "version_only")
    assert any("K9" in n for n in v.notes)


def test_unknown_identity_is_ex(snap, event):
    v = classify(package_from_purl("pkg:generic/php"), snap, event)
    assert v.exposure_class == "EX" and v.criteria["reason"] == "identity"


def test_t0_changes_k2(snap):
    late = Event("PHP2Shell", ("CVE-2026-109618", "CVE-2026-109619"),
                 Event.parse_t0("2026-10-21T14:00:00Z") + timedelta(days=500), 90)
    # 8.2 got a release fix for this event, so after its EoSSec it is a courtesy-release E0, with K2 lapsed
    assert upstream_class(snap.upstream["8.2"], late.t0.date(), 90) == ("E0", "lapsed")
    v = classify(package_from_purl("pkg:generic/php@8.2.30"), snap, late)
    assert v.criteria["K2"] == "lapsed" and any("Courtesy release" in n for n in v.notes)


def test_kev_flag(snap, event):
    v = classify(package_from_purl("pkg:generic/php@8.5.12"), snap, event,
                 EngineOptions(exploited_cves={"CVE-2026-109618"}))
    assert v.criteria["K13"] is True


def test_courtesy_release_on_ended_branch_follows_paper(snap, event):
    """An ended branch that still gets an upstream release fix is E0 in the paper's code."""
    import dataclasses
    from eox_scan.reference import paper_reference
    ub = dataclasses.replace(snap.upstream["7.4"], remediation="release", fixed_version="7.4.34")
    assert upstream_class(ub, event.t0.date(), 90)[0] == "E0"
    row = {"branch": "7.4", "end_of_life": "2022-11-28", "end_of_security_support": "2022-11-28",
           "upstream_fix": "release", "provenance": "confirmed"}
    assert paper_reference.classify_branch(row, 90).cls == "E0"
