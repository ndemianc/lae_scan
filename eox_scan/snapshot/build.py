"""Build a frozen snapshot directory from the CSV sources:

  <out>/eox.db                      lifecycle, advisories, feeds (SQLite)
  <out>/xeol-cache/1/xeol.db        PHP-only database in xeol's schema v1
  <out>/xeol-cache/1/metadata.json  xeol curator metadata (sha256 of xeol.db)
  <out>/xeol-db_v1.tar.gz           same, as an archive for `xeol db import`
  <out>/openeox/*.json              OpenEoX Shell documents emitted per supplier
  <out>/manifest.json               SHA-256 of every file above

Builds are deterministic: the same inputs and as-of date give identical hashes.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import sqlite3
import tarfile
from typing import Dict, List

from . import CSV_FILES, Snapshot
from .openeox import shell_documents, validate_core

DB_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE upstream_branches (
  branch TEXT PRIMARY KEY, general_availability TEXT, end_of_active_support TEXT,
  end_of_security_support TEXT, end_of_life TEXT, last_release TEXT, upstream_fix TEXT,
  fixed_version TEXT, provenance TEXT NOT NULL, provenance_basis TEXT, source TEXT NOT NULL);
CREATE TABLE supplier_lifecycle (
  family TEXT NOT NULL, distro TEXT NOT NULL, tier TEXT NOT NULL, end_of_security_support TEXT,
  access TEXT NOT NULL, mr_level TEXT NOT NULL, source_url TEXT NOT NULL);
CREATE TABLE advisory_status (
  cve TEXT NOT NULL, family TEXT NOT NULL, distro TEXT, package TEXT NOT NULL, upstream_branch TEXT,
  fixed_version TEXT, status TEXT NOT NULL, advisory TEXT, source_url TEXT NOT NULL, retrieved TEXT);
CREATE TABLE supplier_feeds (
  vendor TEXT PRIMARY KEY, fix_status_mr TEXT, fix_status_format TEXT, lifecycle_mr TEXT,
  lifecycle_format TEXT, openeox TEXT, source TEXT);
"""

# xeol schema v1, as queried by xeol/db/v1/store/store.go
XEOL_SCHEMA = """
CREATE TABLE id (build_timestamp TEXT, schema_version INTEGER);
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, permalink TEXT);
CREATE TABLE cycles (id INTEGER PRIMARY KEY, product_id INTEGER, release_cycle TEXT, eol DATETIME,
  eol_bool NUMERIC, lts TEXT, latest_release TEXT, latest_release_date DATETIME, release_date DATETIME);
CREATE TABLE purls (id INTEGER PRIMARY KEY, product_id INTEGER, purl TEXT);
CREATE TABLE cpes (id INTEGER PRIMARY KEY, product_id INTEGER, cpe TEXT);
CREATE TABLE vulns (id INTEGER PRIMARY KEY, product_id INTEGER, version TEXT, issue_count INTEGER);
"""


def _rows(src: str, key: str) -> List[Dict[str, str]]:
    with open(os.path.join(src, CSV_FILES[key]), newline="") as f:
        return list(csv.DictReader(f))


def _insert(con, table: str, rows: List[Dict[str, str]]) -> None:
    if not rows:
        return
    cols = list(rows[0].keys())
    con.executemany(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                    [[r.get(c) for c in cols] for r in rows])


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def xeol_purls(snap: Snapshot) -> List[str]:
    """Short purls (xeol cuts at '@') under which PHP is published across the suppliers in scope."""
    branches = sorted(snap.upstream, key=lambda b: tuple(int(x) for x in b.split(".")))
    names = set()
    for b in branches:
        maj, mnr = b.split(".")
        names.update({f"php{b}", f"php{b}-cli", f"php{b}-fpm", f"php{b}-cgi", f"php{b}-common",
                      f"libapache2-mod-php{b}"})                      # Debian / Ubuntu
        names.update({f"php{maj}{mnr}", f"php{maj}{mnr}-fpm", f"php{maj}{mnr}-cli"})   # Alpine, SUSE php74
    out = set()
    for n in sorted(names):
        out.update({f"pkg:deb/debian/{n}", f"pkg:deb/ubuntu/{n}", f"pkg:apk/alpine/{n}", f"pkg:rpm/suse/{n}"})
    for n in ("php5", "php5-cli", "php5-fpm", "php7", "php8", "php7-cli", "php8-cli", "php7-fpm", "php8-fpm"):
        out.update({f"pkg:deb/ubuntu/{n}", f"pkg:rpm/suse/{n}", f"pkg:rpm/opensuse/{n}"})
    for ns in ("redhat", "centos", "remi", "rocky", "almalinux", "fedora"):
        for n in ("php", "php-cli", "php-fpm", "php-common", "php-main", "php8.4", "php73-php"):
            out.add(f"pkg:rpm/{ns}/{n}")
    for n in ("php", "php-cli", "php-fpm", "libphp"):
        out.add(f"pkg:generic/{n}")
    return sorted(out)


def _xeol_ts(d) -> str:
    return f"{d.isoformat()} 00:00:00+00:00" if d else None


def build_xeol_db(snap: Snapshot, path: str, built: str) -> None:
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(XEOL_SCHEMA)
    con.execute("INSERT INTO id VALUES (?, ?)", (built, 1))
    con.execute("INSERT INTO products VALUES (1, 'PHP', 'php')")
    for i, b in enumerate(sorted(snap.upstream, key=lambda b: tuple(int(x) for x in b.split("."))), start=1):
        u = snap.upstream[b]
        con.execute("INSERT INTO cycles VALUES (?,?,?,?,?,?,?,?,?)",
                    (i, 1, b, _xeol_ts(u.end_of_security_support), 0, "", u.last_release, None,
                     _xeol_ts(u.general_availability)))
    con.executemany("INSERT INTO purls (product_id, purl) VALUES (1, ?)", [(p,) for p in xeol_purls(snap)])
    con.execute("INSERT INTO cpes (product_id, cpe) VALUES (1, 'cpe:2.3:a:php:php')")
    con.commit()
    con.close()


def _det_targz(out: str, files: Dict[str, str]) -> None:
    """Deterministic tar.gz (fixed mtimes, owners and order)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for arcname in sorted(files):
            with open(files[arcname], "rb") as f:
                data = f.read()
            info = tarfile.TarInfo(arcname)
            info.size, info.mtime, info.mode, info.uid, info.gid = len(data), 0, 0o644, 0, 0
            tar.addfile(info, io.BytesIO(data))
    with open(out, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            gz.write(buf.getvalue())


def build(src: str, out: str, as_of: str, openeox_schema: str = "") -> Dict[str, str]:
    os.makedirs(out, exist_ok=True)
    built = f"{as_of}T00:00:00Z"

    # eox.db
    db_path = os.path.join(out, "eox.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    con = sqlite3.connect(db_path)
    con.executescript(DB_SCHEMA)
    con.executemany("INSERT INTO meta VALUES (?, ?)", [("as_of", as_of), ("built", built), ("schema", "1")])
    _insert(con, "upstream_branches", _rows(src, "upstream"))
    _insert(con, "supplier_lifecycle", _rows(src, "lifecycle"))
    _insert(con, "advisory_status", _rows(src, "advisories"))
    _insert(con, "supplier_feeds", _rows(src, "feeds"))
    con.commit()
    con.close()

    snap = Snapshot.from_db(db_path)

    # xeol database for the baseline
    xdir = os.path.join(out, "xeol-cache", "1")
    os.makedirs(xdir, exist_ok=True)
    xdb = os.path.join(xdir, "xeol.db")
    build_xeol_db(snap, xdb, built)
    with open(os.path.join(xdir, "metadata.json"), "w") as f:
        json.dump({"built": built, "version": 1, "checksum": f"sha256:{_sha(xdb)}"}, f, indent=2)
    _det_targz(os.path.join(out, "xeol-db_v1.tar.gz"),
               {"xeol.db": xdb, "metadata.json": os.path.join(xdir, "metadata.json")})

    # OpenEoX Shell documents
    odir = os.path.join(out, "openeox")
    os.makedirs(odir, exist_ok=True)
    problems = []
    for name, doc in shell_documents(snap, built).items():
        for st in doc["statements"]:
            problems += [f"{name}: {p}" for p in validate_core(st["core"], openeox_schema)]
        with open(os.path.join(odir, name), "w") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
            f.write("\n")
    if problems:
        raise ValueError("OpenEoX Core validation failed:\n" + "\n".join(problems))

    # manifest
    files = {}
    for root, _, names in os.walk(out):
        for n in sorted(names):
            p = os.path.join(root, n)
            rel = os.path.relpath(p, out)
            if rel != "manifest.json":
                files[rel] = _sha(p)
    manifest = {"as_of": as_of, "source": os.path.relpath(src), "files": dict(sorted(files.items()))}
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return manifest["files"]
