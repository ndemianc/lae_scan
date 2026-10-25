# eox-scan

`eox-scan` tells you whether a vulnerable package is exposed **because its software lifecycle ended**, and whether
anyone in your supply path will still fix it. It is the proof of concept for the paper
*When No Patch Is Coming: Criteria for Lifecycle-Attributable Vulnerability Exposure, Validated on PHP2Shell*.
The name comes from EoX, "end of X" (end of life, end of security support), the term used by
[OASIS OpenEoX](https://www.oasis-open.org/committees/openeox/).

A version scanner answers "is this version older than the fix?". An end-of-life scanner such as
[xeol](https://github.com/xeol-io/xeol) answers "is upstream still supporting this branch?". Neither answers the question an
operator has to act on: *will a fix reach this build, from the supplier that actually built it?* For PHP2Shell
(CVE-2026-109618, CVE-2026-109619), PHP 7.4 on Ubuntu 20.04 ESM, Debian ELTS or RHEL 8 is fixed even though upstream PHP 7.4
ended in 2022, while PHP 8.0 from Remi on CentOS 7 is not, even though the same upstream source patch exists.

The scope is PHP only, for now.

## Exposure classes

The paper calls this lifecycle-attributable exposure; each package gets one of these classes per vulnerability event.

| Class | Meaning | What to do |
|---|---|---|
| **E0** | Upstream supports the branch and has released a fix | Update |
| **E1** | As E0, but upstream security support ends within the horizon (default 90 days) | Update, plan migration |
| **E2** | Upstream security support has ended; only a source patch exists | Build the patch, migrate, or buy extended support |
| **E3** | Upstream security support has ended; no fix will be published | Migrate, isolate, or buy extended support |
| **EX** | Affectedness of the branch is not established | Verify before acting |
| **D+** | Upstream ended, but the build's own supplier has shipped a fix | Keep receiving supplier updates |
| **D~** | Upstream ended, the supplier is committed (fix pending, or a support tier you can use) | Apply the fix when released |

E2 and E3 are *lifecycle-attributable* when some supported branch is fixed (criterion K5). See
[docs/CLASSES.md](docs/CLASSES.md) for how each class is decided, with PHP2Shell examples and edge cases. Every verdict carries the
criteria vector K1-K13 and the evidence (advisory, lifecycle source URL) behind it.

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q

# Build the frozen snapshot: eox.db, a PHP-only xeol database, OpenEoX documents, manifest
eox-scan snapshot build --out build/snapshot --as-of 2026-10-22

# Classify the PHP packages in a Syft JSON or CycloneDX SBOM
eox-scan scan tests/fixtures/syft_debian11.json --snapshot build/snapshot --format table
eox-scan scan sbom.json --snapshot build/snapshot --baseline emulate -o result.json
eox-scan scan sbom.json --snapshot build/snapshot --format csaf-vex -o vex.json
eox-scan scan sbom.json --entitlement freexian-elts --entitlement ubuntu:esm --fail-on-class E2,E3

# Scan an image or directory directly (needs a pinned Syft, see "Phase 0")
eox-scan scan registry:php:7.4-apache --snapshot build/snapshot   # registry: skips the Docker daemon

# Reproduce the paper's evaluation from scanner inputs
eox-scan replay --snapshot build/snapshot
```

`scan` options: `--event` and `--cve`/`--t0` for events other than PHP2Shell, `--horizon` for K2, `--entitlement` for
subscription tiers you have (Ubuntu Pro, Freexian ELTS), `--kev` with the CISA KEV JSON for K13, and `--fail-on-class` for
CI gates (exit code 3).

## Replay: the paper's numbers, derived by the engine

The paper scores the frameworks against the labelled build records. `eox-scan replay` instead feeds the 75 builds to the
engine as a CycloneDX SBOM (only purl, RPM vendor and distro qualifier, see `scripts/make_replay.py`) and compares what the
engine derives from the snapshot with the labels. It reproduces every count in the paper (primary set, 61 builds):

| Predictor | Fix status acc. (n=53) | Remediability acc. (n=55) |
|---|---|---|
| B1 version string | 0.509 | 0.582 |
| B2 upstream lifecycle | 0.509 | 0.582 |
| B2 as xeol actually matches | n/a | 0.600 (2 false positives) |
| F_today (machine-readable supplier data only) | 0.868 | 0.873 |
| F_full (all supplier data) | 1.000 | 1.000 |

Classes: E0 22, E1 10, E2 6, D+ 23, identical to the paper's reference code for every build (tested).

Read F_full with care: the supplier advisories in the snapshot were transcribed from the same sources as the labels, so
a perfect score shows that the engine resolves suppliers, compares versions and applies support tiers correctly on that
evidence. It is not an independent accuracy estimate. That needs advisories fetched from the live feeds and labels made
separately, on a second event.

The "B2 as xeol" row runs xeol's own matcher (the real binary with `--baseline xeol`, or a line-by-line emulation of
`search/purl.go`). It fails open: 8 RHEL and Ubuntu ESM versions do not parse as semver v1 and are silently not reported,
and version-less entries never match. Here that happens to raise its accuracy slightly, which is the point: the result
depends on parser accidents, not on lifecycle facts.

## How xeol is used

xeol is a baseline, not a dependency. eox-scan never modifies or links it. `snapshot build` writes a PHP-only database in
xeol's schema v1 (`xeol-cache/1/xeol.db` with `metadata.json`, plus `xeol-db_v1.tar.gz` for `xeol db import`), and the
runner calls the unmodified binary offline:

- `XEOL_DB_CACHE_DIR` points at the snapshot; DB auto-update, DB age validation and update checks are off.
- No API key is ever passed (with one, xeol uploads results to xeol.io).
- `--lookahead` is always passed (the code default is 1y; xeol's README says 30d). With no lookahead it is `--lookahead=`,
  which makes xeol match EoL dates before the current time.
- xeol keeps one match per (release cycle, package version) (`xeol/match/matches.go`). Packages that share a version
  string are folded into one finding, and the others are missing from its output. The replay therefore runs xeol once
  per build; a single run over all 75 builds reports 17 EoL matches instead of 23, because five SUSE/openSUSE builds
  share `7.4.33-150400.4.81.1` and three share `8.0.30-150400.4.80.1`. In `scan`, packages folded this way are shown as
  `eol` with `collapsed_into` naming the reported package.
- xeol always evaluates at the wall clock, not at the event time. `replay --baseline xeol` warns when a lifecycle date
  falls between T0 and today, because the binary's verdicts for that branch can then differ from the paper.

## Data

`data/snapshot-2026-10-22/` is the frozen evidence used by the paper, as CSV:

| File | Content |
|---|---|
| `upstream_php_branches.csv` | php.net lifecycle dates, upstream fix kind and affectedness provenance (K6) per branch |
| `supplier_lifecycle.csv` | Debian/Freexian, Ubuntu and Alpine support tiers with access (public or subscription) |
| `supplier_advisories.csv` | per-supplier, per-distro fix status for PHP2Shell (derived from the build records by `scripts/derive_advisories.py`) |
| `supplier_feeds.csv` | whether each supplier publishes fix status and lifecycle in machine-readable form (defines F_today) |

`replay/builds.csv` holds the paper's 80 build records with sources. `eox_scan/reference/paper_reference.py` is the paper's
reference code (`lae.py` in the paper's supplement), vendored unchanged for consistency tests, which is why it keeps
the paper's own identifiers.

OpenEoX Shell documents are emitted from the snapshot. The OASIS schemas are not bundled (license); a built-in check covers
the Core rules, and `--openeox-schema path/to/core.json` validates against the official file when `jsonschema` is installed
(`pip install -e ".[schema]"`).

## Phase 0 (to do with the real tools)

1. Install the tools: `brew install syft`, then `brew tap xeol-io/xeol && brew install xeol` (or the install scripts in
   each project's README).
2. Run `eox-scan tools` to see the paths, versions and SHA-256 sums, then `eox-scan tools --pin` to record them in
   `tools.lock` (until then, pass `--allow-unpinned`). The release checksum files hash the archives, not the binaries,
   and Homebrew may build from source, so a pin taken from a Homebrew install is trust-on-first-use. For a verified pin,
   download the release archive, check it against `checksums.txt`, extract it, and point `EOX_SYFT_BIN` /
   `EOX_XEOL_BIN` at the extracted binaries before pinning.
3. `eox-scan replay --snapshot build/snapshot --baseline xeol` runs the real binary on the replay SBOM. Compare its
   verdicts with the emulation's (`b2_xeol_verdicts` in the summary).
4. Run Syft on a few real images (`eox-scan scan registry:php:7.4-apache --snapshot build/snapshot --baseline xeol --format table`,
   plus Debian 11 with php7.4, Ubuntu 20.04 ESM, RHEL 8 php:7.4, CentOS 7 with Remi) and check the purls, distro
   qualifiers and RPM vendors against `eox_scan/supplier.py`.

## Limitations

- PHP only, one event. Supplier advisories are a frozen snapshot, not live feeds.
- Suppliers without advisories in the snapshot (for example Alpine) get fix status `unknown`, never a guess.
- A generic `pkg:generic/php` found by Syft's binary classifier is judged on the upstream version string only (K9): a distro
  build copied into an image cannot be told apart from an upstream build.

## License

Apache-2.0. Personal work, not affiliated with any employer.
