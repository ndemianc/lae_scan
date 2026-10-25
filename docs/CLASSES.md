# Exposure classes

eox-scan puts every package in one class for one vulnerability event. The class answers one operational question:
**will a fix for this event reach this build, and if not, is that because a software lifecycle ended?**

Classes starting with **E** describe the exposure as upstream leaves it. Classes starting with **D** mean the build's
own downstream supplier (a distribution, an extended-support vendor, a third-party repository) changed that picture.

## How a class is decided

1. **Identify the branch.** From the package version (`7.4.33-1+deb11u10` gives PHP 7.4), else from the package name
   (`php8.2`, `php74`), else from an SBOM hint. No branch means **EX**.
2. **Is the branch affected?** Criterion K6, provenance of affectedness. Only `confirmed` (a fix or advisory exists for
   the branch) and `reported` (credible research) count. `conflicting`, `unconfirmed` and `unknown` give **EX**.
3. **Upstream class**, from upstream data only:
   - K2, End-of-Security-Support (EoSSec) state at the event time T0: `active`, `imminent` (within the horizon,
     default 90 days) or `lapsed`.
   - K3, what upstream published for the event: `release` (an installable fixed release), `source` (a patch in the
     source tree, no release) or `none`.

   | K3 \ K2 | active | imminent | lapsed |
   |---|---|---|---|
   | release | E0 | E1 | E0 (courtesy release, see below) |
   | source | E0 | E0 | **E2** |
   | none | E0 | E0 | **E3** |

4. **Supplier override (K4), only for E2 and E3.** Read the statements of the supplier that built the package (from
   the purl namespace, distro qualifier and RPM vendor):
   - the installed version is at or above a fixed version the supplier published for this scope: **D+**
   - otherwise, the supplier committed to a fix (an advisory saying `fixed` or `pending` for this scope, or a support
     tier for this distro release that is still running at T0 and that you can use): **D~**
   - an explicit `no_fix` statement blocks the commitment, and the class stays E2 or E3.
5. **Lifecycle-attributable** is true for E2 and E3 when some supported branch has a release fix (K5, the
   counterfactual: had the build been on a supported branch, a fix would exist).

**Remediable** means a fix has reached this build or will reach it through its own supply path: fixed builds, and
E0, E1, D+ and D~, unless the supplier stated it will not fix.

## E0: supported, fix available

**Definition.** Affected branch, upstream security support active at T0 and beyond the horizon, and upstream has
released, or will release through normal updates, an installable fix.

**What it means.** The ordinary case that version scanners already handle. If the package is still vulnerable, the
fix is one update away, from upstream or from the supplier that tracks it.

**Action.** Update. Nothing about the lifecycle needs attention.

**PHP2Shell.** PHP 8.3, 8.4 and 8.5 (fixed in 8.3.36, 8.4.27, 8.5.12). Builds: Debian 13 `php8.4` (B012 vulnerable at
8.4.24, B013 fixed at 8.4.27), Ubuntu 24.04 `php8.3`, RHEL 10, SLES 16, Alpine 3.23/3.24, the Docker `php:8.3+` images.
22 of the 61 primary builds.

**Residual risk (K7).** Bounded: future vulnerabilities on this branch will also be fixed.

## E1: supported, fix available, support ends soon

**Definition.** As E0, but upstream EoSSec falls within the horizon after T0 (default 90 days, `--horizon`).

**What it means.** You can fix this event the normal way, but the next one after EoSSec will find the branch without
upstream fixes. An E1 today is likely to become an E2 or E3 for the next event unless your supplier carries the branch.

**Action.** Update now, and plan the migration or extended support before the EoSSec date.

**PHP2Shell.** PHP 8.2 (fixed in 8.2.35; EoSSec 2026-12-31, 71 days after T0). Builds: Debian 12 `php8.2` (B010, B011),
RHEL 8/9 `php:8.2` modules, SLES 15 SP6, openSUSE Leap 15.6, Remi PHP 8.2, Docker `php:8.2`. 10 of the 61 primary builds. With
`--horizon 30` they become E0: E1 is the one class that depends on a policy setting.

**Residual risk.** Bounded for this event, unbounded from the EoSSec date on.

## E2: support ended, source patch only

**Definition.** Affected branch, upstream EoSSec lapsed before T0, and upstream published only a source patch (a
commit or backport in the branch), no installable release. No supplier fixed or committed for this build.

**What it means.** A fix exists, but nobody in your supply path will turn it into a package for you. The exposure is
**lifecycle-attributable**: the same build on a supported branch would get a release. This is the class a version
scanner gets wrong in both directions: it cannot report "fixed" because no fixed upstream version number exists, and
an end-of-life scanner reports "EoL" without saying that a patch exists.

**Action.** One of: build and maintain the patched package yourself, migrate to a supported branch, or buy extended
support from a supplier that carries the branch (eox-scan lists the tiers it knows for your distro release).

**PHP2Shell.** PHP 7.4, 8.0 and 8.1 (upstream source backports only). Builds: Debian 11 `php7.4` at
`7.4.33-1+deb11u10` (B017) once Debian LTS ended, without Freexian ELTS; Remi `php` 7.4/8.0/8.1 on CentOS 7
(B078-B080, Remi states it will not fix) and Remi's PHP 8.1 for EL9 (B077); Alpine edge `php81` (B063). 6 of the 61
primary builds. Outside the replay, the Docker `php:7.4-apache` image is E2 too: it is built from upstream source and
nobody publishes a fixed 7.4 build.

**Residual risk.** Unbounded: each future vulnerability on the branch needs the same effort, and later ones may not
even get a source patch.

## E3: support ended, no fix at all

**Definition.** Affected branch, upstream EoSSec lapsed, and upstream published nothing for this event. No supplier
fixed or committed for this build.

**What it means.** The strongest lifecycle-attributable case. Unless you write the patch yourself, there is nothing to
apply. Isolation and migration are the only controls left.

**Action.** Migrate, isolate the service (network exposure, WAF rules, disabling the vulnerable feature), or buy
extended support if a supplier carries the branch.

**PHP2Shell.** PHP 5.5, 5.6, 7.0, 7.2 and 7.3 (affected, no upstream fix). 7.1 too, on research reports. In the
replay every E3 build happens to have a supplier that fixed it (Ubuntu ESM, Freexian ELTS, GetPageSpeed), so all of
them are D+. A self-built PHP 7.3, or a distro build without extended support, would be E3.

**Residual risk.** Unbounded.

## EX: affectedness not established

**Definition.** The branch cannot be identified, or its affectedness provenance (K6) is `conflicting`,
`unconfirmed` or `unknown`.

**What it means.** eox-scan will not guess. Saying "vulnerable" would send people to patch a branch that may not be
affected; saying "fine" could hide an exposure. EX is a request for evidence, not a verdict.

**Action.** Establish affectedness: test the vulnerable code path, read the supplier's analysis, or ask the supplier.
Treat the build as exposed until then if it is internet-facing.

**PHP2Shell.** PHP 5.4 is `conflicting` (research says affected; Red Hat says RHEL 7's 5.4-based `php` is not
affected by CVE-2026-109619 and is investigating the other CVE). 5.2 and 5.3 are `unconfirmed`, 4.4-5.1 `unknown`.
Builds: RHEL 7 and RHEL 6 `php` (B037-B040), which the paper also excludes from scoring. A `pkg:generic/php` with no
version is EX for identity.

## D+: upstream ended, your supplier fixed it

**Definition.** The upstream class is E2 or E3, and the installed version is at or above the fixed version that the
build's own supplier published for this distro release and branch.

**What it means.** The lifecycle ended upstream, but not for your supply path. This is the case where an end-of-life
scanner raises a false alarm: xeol reports "EoL" for every one of these builds whose version it can parse, even
though they are fixed (it silently skips the RHEL and Ubuntu ESM versions it cannot parse).

**Action.** Nothing for this event. Keep receiving the supplier's updates, and track the supplier's own end date,
which is now the one that matters (for example Ubuntu 20.04 ESM until 2030-04-23).

**PHP2Shell.** 23 of the 61 primary builds, the largest single group: Ubuntu ESM `php5`/`php7.0`/`php7.2`/`php7.4`
(B021-B024, version contains `+esm`), Ubuntu 22.04 `php8.1`, Freexian ELTS Debian 9/10/11 (B018-B020), RHEL 9
`php` 8.0 and RHEL 8 `php:7.4`, SUSE LTSS `php7`/`php74`/`php8`, openSUSE Leap 15.4, GetPageSpeed on CentOS 7 (5.6, 7.0,
7.3, 8.0).

**Residual risk.** Bounded until the supplier's own support ends.

## D~: upstream ended, your supplier is committed

**Definition.** The upstream class is E2 or E3, the installed version is not fixed, but the build's supplier is
committed: it published `fixed` or `pending` for this scope, or it runs a support tier for this distro release that is
still active at T0 and usable by you. Subscription tiers (Ubuntu Pro ESM, Freexian ELTS) count only with
`--entitlement`, or when the installed build itself comes from that tier (a `+esm` version, or a version the tier
fixed).

**What it means.** The fix will reach you through your normal update channel, either now (update) or when the
supplier ships it. It is not a lifecycle problem for you, provided the entitlement is real.

**Action.** Update if a fixed package exists; otherwise watch for the supplier's release.

**PHP2Shell.** None in the replay, because every supplier that was committed had already shipped. Example: the
Debian 11 `php7.4` build at `7.4.33-1+deb11u10` is E2 by default, and D~ with `--entitlement freexian-elts`, because
ELTS covers Debian 11 until 2031-06-30.

**Residual risk.** Bounded until the supplier's support ends.

## Edge cases

- **Courtesy release.** Upstream sometimes ships a release fix for a branch that is already past EoSSec. That build
  is E0, as in the paper's reference code, with a note: this event is fixable, the next one will not be.
- **Supported branch, no upstream fix yet.** E0: the fix will arrive through normal updates.
- **Supplier refuses on a supported branch.** If upstream still supports the branch but the build's supplier states
  `no_fix` (for example a third-party repository on an ended OS), the class stays E0 or E1, `remediable` is false,
  and a note says the exposure comes from the supplier's lifecycle, not upstream's.
- **Generic builds (K9).** A `pkg:generic/php` found by Syft's binary classifier is judged as an upstream build from
  its version string. A distro build copied into an image cannot be told apart, so the verdict carries a K9 note.

## Mapping to CSAF VEX

| Class | Fixed build | Vulnerable build |
|---|---|---|
| E0, E1, D~ | `fixed` | `known_affected`, remediation `vendor_fix` |
| E2 | `fixed` | `known_affected`, remediation `none_available` (with the options above) |
| E3 | `fixed` | `known_affected`, remediation `no_fix_planned` |
| D+ | `fixed` | n/a |
| EX | `fixed` | `under_investigation` (or `known_affected` with `none_available` if the supplier said vulnerable) |
