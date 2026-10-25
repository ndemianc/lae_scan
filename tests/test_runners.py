"""Runner behaviour with stand-in binaries (the real Syft and xeol are not needed)."""
import json
import os
import stat
from datetime import date

import pytest

from eox_scan import cli
from eox_scan.runners import ToolError, check, find_tool, xeol

FAKE_XEOL = """#!/bin/sh
if [ "$1" = "version" ]; then echo "Application: xeol"; echo "Version: 0.10.8"; exit 0; fi
printf '%s\\n' "$@" > "$FAKE_ARGS"
env | grep '^XEOL_' | sort > "$FAKE_ENV"
cat <<'JSON'
{"matches": [{"Cycle": {"ProductName": "PHP", "ReleaseCycle": "7.4", "Eol": "2022-11-28"},
              "artifact": {"name": "php7.4", "purl": "pkg:deb/debian/php7.4@7.4.33-1%2Bdeb11u10?distro=debian-11"}}]}
JSON
"""


def _exe(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


@pytest.fixture
def fake_xeol(tmp_path, monkeypatch):
    p = _exe(tmp_path / "xeol", FAKE_XEOL)
    monkeypatch.setenv("EOX_XEOL_BIN", p)
    monkeypatch.setenv("FAKE_ARGS", str(tmp_path / "args"))
    monkeypatch.setenv("FAKE_ENV", str(tmp_path / "env"))
    return tmp_path


def test_missing_tool_is_a_clean_error(monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.delenv("EOX_SYFT_BIN", raising=False)
    rc = cli.main(["scan", "php:7.4-apache"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "syft not found" in err and "brew install syft" in err and "Traceback" not in err


def test_unpinned_tool_is_refused(fake_xeol):
    with pytest.raises(ToolError, match="tools --pin"):
        find_tool("xeol", {})
    assert find_tool("xeol", {}, allow_unpinned=True).endswith("xeol")


def test_pin_records_hash_and_version(fake_xeol, tmp_path, monkeypatch):
    monkeypatch.setenv("EOX_SYFT_BIN", os.environ["EOX_XEOL_BIN"])
    lock = tmp_path / "tools.lock"
    lock.write_text("{}")
    rows = check(pin=True, lock_path=str(lock))
    assert all(r["pinned"] and r["version"] == "0.10.8" for r in rows)
    pinned = json.loads(lock.read_text())
    assert find_tool("xeol", pinned)


def test_xeol_runner_is_offline_with_no_lookahead(fake_xeol, built_snapshot, tmp_path):
    sbom = tmp_path / "s.json"
    sbom.write_text("{}")
    res = xeol.scan(str(sbom), built_snapshot, lookahead="", allow_unpinned=True)
    assert res["pkg:deb/debian/php7.4@7.4.33-1%2Bdeb11u10?distro=debian-11"]["cycle"] == "7.4"
    args = (fake_xeol / "args").read_text().split("\n")
    assert "--lookahead=" in args and "-o" in args and args[0] == f"sbom:{sbom}"
    env = (fake_xeol / "env").read_text()
    assert "XEOL_DB_AUTO_UPDATE=false" in env and "XEOL_API_KEY=\n" in env + "\n"
    assert f"XEOL_DB_CACHE_DIR={os.path.join(built_snapshot, 'xeol-cache')}" in env


def test_xeol_needs_a_built_snapshot(fake_xeol, tmp_path):
    with pytest.raises(ToolError, match="snapshot build"):
        xeol.scan("x.json", str(tmp_path), allow_unpinned=True)


def test_stale_dates(snap, event):
    assert xeol.stale_dates(snap, event.t0.date(), date(2026, 10, 25)) == []
    assert xeol.stale_dates(snap, event.t0.date(), date(2027, 1, 5)) == ["PHP 8.2 (2026-12-31)"]


FAKE_SYFT = """#!/bin/sh
if [ "$1" = "version" ]; then echo "Version: 1.55.0"; exit 0; fi
if [ -n "$FAKE_SYFT_SLEEP" ]; then sleep "$FAKE_SYFT_SLEEP"; fi
for a in "$@"; do case "$a" in syft-json=*) cp "$FAKE_SYFT_FIXTURE" "${a#syft-json=}";; esac; done
"""


@pytest.fixture
def fake_syft(tmp_path, monkeypatch):
    from conftest import FIXTURES
    p = _exe(tmp_path / "syft", FAKE_SYFT)
    monkeypatch.setenv("EOX_SYFT_BIN", p)
    monkeypatch.setenv("FAKE_SYFT_FIXTURE", os.path.join(FIXTURES, "syft_debian11.json"))
    return tmp_path


def test_scan_image_through_syft(fake_syft, built_snapshot, tmp_path):
    out = tmp_path / "r.txt"
    rc = cli.main(["scan", "registry:php:7.4-apache", "--snapshot", built_snapshot, "--allow-unpinned",
                   "--format", "table", "-o", str(out)])
    assert rc == 0 and "php7.4-cli" in out.read_text()


def test_syft_hang_times_out_with_registry_hint(fake_syft, built_snapshot, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_SYFT_SLEEP", "5")
    rc = cli.main(["scan", "php:7.4-apache", "--snapshot", built_snapshot, "--allow-unpinned",
                   "--syft-timeout", "1"])
    err = capsys.readouterr().err
    assert rc == 2 and "within 1s" in err and "registry:php:7.4-apache" in err and "Traceback" not in err


# A stand-in that behaves like xeol's matcher on the snapshot and, like xeol, keeps
# one match per (cycle, version): later packages with the same version are dropped.
DEDUP_XEOL = r"""#!/usr/bin/env python3
import json, sys
if sys.argv[1] == "version":
    print("Version: 0.10.8"); sys.exit(0)
doc = json.load(open(sys.argv[1][len("sbom:"):]))
eol = {"7.4": "2022-11-28", "8.0": "2023-11-26"}
seen, matches = set(), []
for c in doc.get("components", []):
    v = c.get("version") or ""
    cyc = ".".join(v.split(".")[:2])
    if cyc in eol and (cyc, v) not in seen:
        seen.add((cyc, v))
        matches.append({"Cycle": {"ProductName": "PHP", "ReleaseCycle": cyc, "Eol": eol[cyc]},
                        "artifact": {"name": c["name"], "version": v, "purl": c["purl"]}})
print(json.dumps({"matches": matches}))
"""


def test_xeol_dedup_hides_builds_unless_run_per_build(tmp_path, monkeypatch, built_snapshot, snap, event):
    from conftest import ROOT
    from eox_scan import replay
    monkeypatch.setenv("EOX_XEOL_BIN", _exe(tmp_path / "xeol", DEDUP_XEOL))
    sbom = os.path.join(ROOT, "replay", "php2shell.cdx.json")
    combined = xeol.scan(sbom, built_snapshot, allow_unpinned=True)
    each = xeol.scan_each(sbom, built_snapshot, allow_unpinned=True)
    # SUSE/openSUSE share 7.4.33-150400.4.81.1 (5 builds) and 8.0.30-150400.4.80.1 (3 builds)
    suse74 = [k for k in each if "7.4.33-150400.4.81.1" in k]
    assert len(suse74) == 5 and sum("7.4.33-150400.4.81.1" in k for k in combined) == 1
    res = replay.run(sbom, os.path.join(ROOT, "replay", "ground_truth.csv"), snap, event, xeol_verdicts=each)
    assert res["primary"]["remediability"]["B2_xeol"]["fn"] > \
        replay.run(sbom, os.path.join(ROOT, "replay", "ground_truth.csv"), snap, event,
                   xeol_verdicts=combined)["primary"]["remediability"]["B2_xeol"]["fn"]


def test_expand_collapsed_marks_hidden_packages():
    from eox_scan.supplier import package_from_purl
    a = package_from_purl("pkg:generic/php@7.4.33")
    b = package_from_purl("pkg:generic/php-cli@7.4.33")
    out = xeol.expand_collapsed([a, b], {a.purl: {"verdict": "eol", "cycle": "7.4"}})
    assert out[b.purl]["verdict"] == "eol" and out[b.purl]["collapsed_into"] == a.purl
