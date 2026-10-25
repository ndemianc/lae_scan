import pytest

from eox_scan.baseline.xeol_emulation import SEMVER_V1, normalize_semver
from eox_scan.versions import branch_of, compare, upstream_part

# The version strings that break naive or semver-only comparison
HARD = [
    ("rpm", "8.0.30-8.el9_8.1", "8.0.30-8.el9_8", 1),                       # '_' in the RPM release
    ("rpm", "8.2.35-1.module+el9.8.0+25111+a1450321", "8.2.35-1.module+el9.8.0+24000+aaaa", 1),
    ("deb", "5.5.9+dfsg-1ubuntu4.29+esm18", "5.5.9+dfsg-1ubuntu4.29+esm9", 1),   # double '+', numeric esm
    ("deb", "7.4.33-1+deb11u14", "7.4.33-1+deb11u10", 1),
    ("deb", "7.3.31-1~deb10u16", "7.3.31-1", -1),                           # '~' sorts before
    ("deb", "1:7.4.3-1", "7.4.33-1", 1),                                   # epoch wins
    ("apk", "8.1.34-r6", "8.1.34-r10", -1),
    ("generic", "8.6.0RC4", "8.6.0", -1),                                  # pre-release first
]


@pytest.mark.parametrize("ptype,a,b,expected", HARD)
def test_hard_strings(ptype, a, b, expected):
    assert compare(ptype, a, b) == expected
    assert compare(ptype, b, a) == -expected


def test_unparseable_is_none_not_a_guess():
    assert compare("deb", "not a version!", "1.0") is None
    assert compare("generic", "x", "1.0") is None
    assert compare("rpm", None, "1.0") is None


def test_upstream_part_and_branch():
    assert upstream_part("rpm", "8.0.30-8.el9_8.1") == "8.0.30"
    assert upstream_part("deb", "1:5.5.9+dfsg-1ubuntu4.29+esm18") == "5.5.9+dfsg"
    assert upstream_part("generic", "8.4.27") == "8.4.27"
    assert branch_of("5.5.9+dfsg") == "5.5"
    assert branch_of("8") is None


@pytest.mark.parametrize("v", ["8.0.30-8.el9_8.1", "5.5.9+dfsg-1ubuntu4.29+esm18"])
def test_xeol_semver_v1_rejects(v):
    """xeol drops these packages: the semver v1 regex cannot parse them (fail-open)."""
    assert SEMVER_V1.match(normalize_semver(v)) is None


def test_xeol_normalizes_debian_tilde():
    assert normalize_semver("8.2.32-1~deb12u1") == "8.2.32"
