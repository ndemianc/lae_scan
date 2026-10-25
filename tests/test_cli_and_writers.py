import json
import os

from conftest import FIXTURES, ROOT

from eox_scan import cli, sbom, writers
from eox_scan.engine import classify


def test_scan_syft_json_groups_binaries_and_fails_on_class(tmp_path, built_snapshot):
    out = tmp_path / "r.json"
    rc = cli.main(["scan", os.path.join(FIXTURES, "syft_debian11.json"), "--snapshot", built_snapshot,
                   "--baseline", "emulate", "-o", str(out), "--fail-on-class", "E2,E3"])
    assert rc == 3
    doc = json.loads(out.read_text())
    res = {r["package"]["purl"].split("@")[0]: r for r in doc["results"]}
    assert set(res) == {"pkg:deb/debian/php7.4-cli", "pkg:generic/php-cli"}
    deb = res["pkg:deb/debian/php7.4-cli"]
    assert deb["exposure"]["class"] == "E2" and any("php7.4-fpm" in n for n in deb["exposure"]["notes"])
    assert deb["baseline"]["xeol"]["verdict"] == "eol"


def test_scan_third_party_rpm_vendors(tmp_path, built_snapshot):
    rc = cli.main(["scan", os.path.join(FIXTURES, "syft_centos7_remi.json"), "--snapshot", built_snapshot,
                   "--format", "table", "-o", str(tmp_path / "t.txt"), "--fail-on-class", "E3"])
    assert rc == 0
    text = (tmp_path / "t.txt").read_text()
    assert "remi" in text and "getpagespeed" in text and "D+" in text


def test_csaf_vex_shape(snap, event):
    pkgs = sbom.read(os.path.join(ROOT, "replay", "php2shell.cdx.json"))
    verdicts = [classify(p, snap, event) for p in pkgs]
    doc = writers.csaf_vex(verdicts, event)
    assert doc["document"]["category"] == "csaf_vex"
    assert [v["cve"] for v in doc["vulnerabilities"]] == list(event.cves)
    ps = doc["vulnerabilities"][0]["product_status"]
    ids = {p["product_id"] for p in doc["product_tree"]["full_product_names"]}
    listed = [i for xs in ps.values() for i in xs]
    assert set(listed) <= ids and len(listed) == len(set(listed)), "each product in exactly one status"
    affected = set(ps.get("known_affected", []))
    covered = {i for r in doc["vulnerabilities"][0]["remediations"] for i in r["product_ids"]}
    assert affected <= covered, "CSAF VEX: every known_affected product needs a remediation"


def test_replay_command(capsys):
    assert cli.main(["replay"]) == 0
    out = capsys.readouterr().out
    assert "F_full     1.000" in out


def test_table_shows_baselines(tmp_path, built_snapshot):
    out = tmp_path / "t.txt"
    cli.main(["scan", os.path.join(FIXTURES, "syft_debian11.json"), "--snapshot", built_snapshot,
              "--baseline", "emulate", "--format", "table", "-o", str(out)])
    lines = out.read_text().splitlines()
    assert lines[0].split()[-4:] == ["FIX", "B2", "REMEDIABLE", "XEOL"]
    deb = next(row for row in lines if row.startswith("php7.4-cli"))
    assert deb.split()[-3:] == ["vulnerable", "no", "eol"]
