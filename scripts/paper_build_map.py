"""Mapping of the paper's PHP2Shell build records (replay/builds.csv) to the
identifiers a scanner would see: purl type, namespace, package name, distro
qualifier, supplier family and RPM vendor.

Package names and versions come verbatim from builds.csv. Distro qualifiers
follow Syft's purl conventions (deb: debian-12 / ubuntu-22.04, rpm: rhel-9,
sles-15.6, opensuse-leap-15.6, centos-7, apk: alpine-<branch>).
"""

# build_id: (purl_type, namespace, name, distro, family, vendor)
BUILD_MAP = {
    # PHP upstream source releases (what Syft's binary classifier reports)
    "B001": ("generic", None, "php", None, "php", None),
    "B002": ("generic", None, "php", None, "php", None),
    "B003": ("generic", None, "php", None, "php", None),
    "B004": ("generic", None, "php", None, "php", None),
    # Debian (security and LTS tiers)
    "B010": ("deb", "debian", "php8.2", "debian-12", "debian", None),
    "B011": ("deb", "debian", "php8.2", "debian-12", "debian", None),
    "B012": ("deb", "debian", "php8.4", "debian-13", "debian", None),
    "B013": ("deb", "debian", "php8.4", "debian-13", "debian", None),
    "B014": ("deb", "debian", "php8.4", "debian-14", "debian", None),
    "B015": ("deb", "debian", "php8.4", "debian-sid", "debian", None),
    "B016": ("deb", "debian", "php8.2", "debian-sid", "debian", None),
    "B017": ("deb", "debian", "php7.4", "debian-11", "debian", None),
    # Freexian ELTS builds of Debian packages
    "B018": ("deb", "debian", "php7.4", "debian-11", "debian", None),
    "B019": ("deb", "debian", "php7.3", "debian-10", "debian", None),
    "B020": ("deb", "debian", "php7.0", "debian-9", "debian", None),
    # Ubuntu
    "B021": ("deb", "ubuntu", "php5", "ubuntu-14.04", "ubuntu", None),
    "B022": ("deb", "ubuntu", "php7.0", "ubuntu-16.04", "ubuntu", None),
    "B023": ("deb", "ubuntu", "php7.2", "ubuntu-18.04", "ubuntu", None),
    "B024": ("deb", "ubuntu", "php7.4", "ubuntu-20.04", "ubuntu", None),
    "B025": ("deb", "ubuntu", "php8.1", "ubuntu-22.04", "ubuntu", None),
    "B026": ("deb", "ubuntu", "php8.3", "ubuntu-24.04", "ubuntu", None),
    "B027": ("deb", "ubuntu", "php8.5", "ubuntu-26.04", "ubuntu", None),
    "B028": ("deb", "ubuntu", "php8.5", "ubuntu-26.10", "ubuntu", None),
    # Red Hat
    "B029": ("rpm", "redhat", "php", "rhel-10", "redhat", "Red Hat, Inc."),
    "B030": ("rpm", "redhat", "php8.4", "rhel-10", "redhat", "Red Hat, Inc."),
    "B031": ("rpm", "redhat", "php", "rhel-9", "redhat", "Red Hat, Inc."),
    "B032": ("rpm", "redhat", "php", "rhel-9", "redhat", "Red Hat, Inc."),
    "B033": ("rpm", "redhat", "php", "rhel-9", "redhat", "Red Hat, Inc."),
    "B034": ("rpm", "redhat", "php", "rhel-9", "redhat", "Red Hat, Inc."),
    "B035": ("rpm", "redhat", "php", "rhel-8", "redhat", "Red Hat, Inc."),
    "B036": ("rpm", "redhat", "php", "rhel-8", "redhat", "Red Hat, Inc."),
    "B037": ("rpm", "redhat", "php", "rhel-7", "redhat", "Red Hat, Inc."),
    "B038": ("rpm", "redhat", "php", "rhel-7", "redhat", "Red Hat, Inc."),
    "B039": ("rpm", "redhat", "php", "rhel-6", "redhat", "Red Hat, Inc."),
    "B040": ("rpm", "redhat", "php", "rhel-6", "redhat", "Red Hat, Inc."),
    "B041": ("rpm", "redhat", "php-main", "rhel-hummingbird", "redhat", "Red Hat, Inc."),
    # SUSE and openSUSE
    "B042": ("rpm", "suse", "php74", "sles-12.5", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B043": ("rpm", "suse", "php8", "sles-15.4", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B044": ("rpm", "suse", "php7", "sles-15.4", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B045": ("rpm", "suse", "php8", "sles-15.5", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B046": ("rpm", "suse", "php7", "sles-15.5", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B047": ("rpm", "suse", "php8", "sles-15.6", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B048": ("rpm", "suse", "php7", "sles-15.6", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B049": ("rpm", "suse", "php8", "sles-15.7", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B050": ("rpm", "suse", "php7", "sles-15.7", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B051": ("rpm", "suse", "php8", "sles-16.0", "suse", "SUSE LLC <https://www.suse.com/>"),
    "B052": ("rpm", "opensuse", "php8", "opensuse-leap-15.6", "opensuse", "openSUSE"),
    "B053": ("rpm", "opensuse", "php8", "opensuse-leap-15.4", "opensuse", "openSUSE"),
    "B054": ("rpm", "opensuse", "php7", "opensuse-leap-15.4", "opensuse", "openSUSE"),
    "B055": ("rpm", "opensuse", "php8", "opensuse-tumbleweed", "opensuse", "openSUSE"),
    # Alpine
    "B056": ("apk", "alpine", "php83", "alpine-3.24", "alpine", None),
    "B057": ("apk", "alpine", "php84", "alpine-3.24", "alpine", None),
    "B058": ("apk", "alpine", "php85", "alpine-3.24", "alpine", None),
    "B059": ("apk", "alpine", "php83", "alpine-3.23", "alpine", None),
    "B060": ("apk", "alpine", "php84", "alpine-3.23", "alpine", None),
    "B061": ("apk", "alpine", "php85", "alpine-3.23", "alpine", None),
    "B062": ("apk", "alpine", "php82", "alpine-edge", "alpine", None),
    "B063": ("apk", "alpine", "php81", "alpine-edge", "alpine", None),
    # Docker official images (PHP built from upstream source)
    "B064": ("generic", None, "php", None, "docker-official", None),
    "B065": ("generic", None, "php", None, "docker-official", None),
    "B066": ("generic", None, "php", None, "docker-official", None),
    "B067": ("generic", None, "php", None, "docker-official", None),
    # GetPageSpeed extras for CentOS 7
    "B068": ("rpm", "centos", "php", "centos-7", "getpagespeed", "GetPageSpeed"),
    "B069": ("rpm", "centos", "php", "centos-7", "getpagespeed", "GetPageSpeed"),
    "B070": ("rpm", "centos", "php73-php", "centos-7", "getpagespeed", "GetPageSpeed"),
    "B071": ("rpm", "centos", "php", "centos-7", "getpagespeed", "GetPageSpeed"),
    "B072": ("rpm", "centos", "php", "centos-7", "getpagespeed", "GetPageSpeed"),
    # Remi repository
    "B073": ("rpm", "remi", "php", "rhel-9", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
    "B074": ("rpm", "remi", "php", "rhel-9", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
    "B075": ("rpm", "remi", "php", "rhel-9", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
    "B076": ("rpm", "remi", "php", "rhel-9", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
    "B077": ("rpm", "remi", "php", "rhel-9", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
    "B078": ("rpm", "centos", "php", "centos-7", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
    "B079": ("rpm", "centos", "php", "centos-7", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
    "B080": ("rpm", "centos", "php", "centos-7", "remi", "Remi's RPM repository <https://rpms.remirepo.net/>"),
}
