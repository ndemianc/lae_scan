import hashlib
import json
import os
import sqlite3
import tarfile

from conftest import SRC

from eox_scan.snapshot import Snapshot
from eox_scan.snapshot.build import build
from eox_scan.snapshot.openeox import CORE_ID, validate_core


def test_build_is_deterministic(built_snapshot, tmp_path):
    again = build(SRC, str(tmp_path), "2026-10-22")
    with open(os.path.join(built_snapshot, "manifest.json")) as f:
        assert json.load(f)["files"] == again


def test_csv_and_db_load_identically(snap, built_snapshot):
    db = Snapshot.load(built_snapshot)
    assert (db.upstream, db.lifecycle, db.advisories, db.as_of) == \
        (snap.upstream, snap.lifecycle, snap.advisories, snap.as_of)


def test_xeol_db_layout(built_snapshot):
    d = os.path.join(built_snapshot, "xeol-cache", "1")
    with open(os.path.join(d, "metadata.json")) as f:
        meta = json.load(f)
    with open(os.path.join(d, "xeol.db"), "rb") as f:
        assert meta["checksum"] == "sha256:" + hashlib.sha256(f.read()).hexdigest()
    assert meta["version"] == 1
    con = sqlite3.connect(os.path.join(d, "xeol.db"))
    assert con.execute("SELECT schema_version FROM id").fetchone() == (1,)
    assert set(r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")) >= \
        {"id", "products", "cycles", "purls", "cpes", "vulns"}
    assert con.execute("SELECT eol FROM cycles WHERE release_cycle='8.1'").fetchone() == ("2025-12-31 00:00:00+00:00",)
    purls = {r[0] for r in con.execute("SELECT purl FROM purls")}
    assert {"pkg:deb/debian/php8.2", "pkg:rpm/redhat/php", "pkg:apk/alpine/php83", "pkg:generic/php-cli"} <= purls
    assert all("@" not in p for p in purls), "xeol looks up short purls (cut at '@')"
    with tarfile.open(os.path.join(built_snapshot, "xeol-db_v1.tar.gz")) as t:
        assert sorted(t.getnames()) == ["metadata.json", "xeol.db"]


def test_openeox_documents_pass_core_check(built_snapshot):
    odir = os.path.join(built_snapshot, "openeox")
    names = sorted(os.listdir(odir))
    assert "php.json" in names and "debian.json" in names
    for n in names:
        with open(os.path.join(odir, n)) as f:
            doc = json.load(f)
        for st in doc["statements"]:
            assert validate_core(st["core"]) == []
            assert set(st) == {"core", "product", "product_identification_helper"}


def test_core_check_catches_errors():
    bad = {"$schema": CORE_ID, "end_of_life": "2026-13-01", "last_updated": "yesterday", "extra": 1}
    problems = validate_core(bad)
    assert any("end_of_security_support" in p for p in problems)
    assert any("unexpected property extra" in p for p in problems)
    assert any("last_updated" in p for p in problems)
