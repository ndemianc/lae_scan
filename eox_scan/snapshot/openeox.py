"""Emit the snapshot's lifecycle data as OpenEoX Shell documents and check them.

Field names follow the OASIS OpenEoX TC draft schemas (core.json, shell.json,
product_software.json at github.com/oasis-tcs/openeox, `tbd` version path).
The schemas are not bundled (OASIS license). `validate_core` is a built-in
structural check of the Core rules; pass `--openeox-schema <core.json>` to also
validate against the official file with `jsonschema` when it is installed.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import date
from typing import Dict, List, Optional

BASE = "https://docs.oasis-open.org/openeox/tbd/schema/"
CORE_ID, SHELL_ID, SOFTWARE_ID = BASE + "core.json", BASE + "shell.json", BASE + "product_software.json"
CORE_KEYS = {"$schema", "end_of_life", "end_of_sales", "end_of_security_support", "last_updated"}
CORE_REQUIRED = {"$schema", "end_of_life", "end_of_security_support", "last_updated"}
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")

PRODUCTS = {
    "debian": ("Debian", "Debian GNU/Linux"),
    "freexian-elts": ("Freexian", "Debian GNU/Linux ELTS"),
    "ubuntu": ("Canonical", "Ubuntu"),
    "alpine": ("Alpine Linux", "Alpine Linux"),
}


def _ts(d: Optional[date]) -> str:
    return f"{d.isoformat()}T00:00:00Z" if d else "tba"


def _core(eol: Optional[date], eossec: Optional[date], updated: str) -> Dict:
    return {"$schema": CORE_ID, "end_of_life": _ts(eol), "end_of_security_support": _ts(eossec),
            "last_updated": updated}


def _statement(core: Dict, vendor: str, product: str, version: str, purls: List[str]) -> Dict:
    st = {"core": core,
          "product": {"$schema": SOFTWARE_ID, "vendor_name": vendor, "product_name": product,
                      "product_version": version},
          "product_identification_helper": {}}
    if purls:
        st["product_identification_helper"]["purls"] = purls
    return st


def shell_documents(snap, built: str) -> Dict[str, Dict]:
    """{file name: Shell document}: one for upstream PHP, one per supplier family with tiers."""
    docs: Dict[str, Dict] = {}
    php = []
    for b in sorted(snap.upstream, key=lambda b: tuple(int(x) for x in b.split("."))):
        u = snap.upstream[b]
        php.append(_statement(_core(u.end_of_life, u.end_of_security_support, built), "The PHP Group", "PHP", b,
                              [f"pkg:generic/php@{u.last_release}"] if u.last_release else []))
    docs["php.json"] = {"$schema": SHELL_ID, "statements": php}

    by_family = defaultdict(list)
    for t in snap.lifecycle:
        by_family[t.family].append(t)
    for family, tiers in sorted(by_family.items()):
        vendor, product = PRODUCTS.get(family, (family, family))
        last = defaultdict(lambda: None)   # distro -> end of the last tier (end of life)
        for t in tiers:
            if t.end_of_security_support and (last[t.distro] is None or t.end_of_security_support > last[t.distro]):
                last[t.distro] = t.end_of_security_support
        sts = []
        for t in sorted(tiers, key=lambda t: (t.distro, t.end_of_security_support or date.max)):
            version = t.distro.split("-", 1)[-1]
            name = product if t.tier in ("security", "standard", "community") else f"{product} ({t.tier}, {t.access})"
            sts.append(_statement(_core(last[t.distro], t.end_of_security_support, built), vendor, name, version, []))
        docs[f"{family}.json"] = {"$schema": SHELL_ID, "statements": sts}
    return docs


def validate_core(core: Dict, schema_path: str = "") -> List[str]:
    problems = []
    for k in sorted(CORE_REQUIRED - core.keys()):
        problems.append(f"missing {k}")
    for k in sorted(core.keys() - CORE_KEYS):
        problems.append(f"unexpected property {k}")
    if core.get("$schema") != CORE_ID:
        problems.append("$schema is not the Core schema id")
    for k in ("end_of_life", "end_of_sales", "end_of_security_support"):
        v = core.get(k)
        if v is not None and v != "tba" and not (isinstance(v, str) and _RFC3339.match(v)):
            problems.append(f"{k} is neither an RFC 3339 date-time nor 'tba': {v!r}")
    if not (isinstance(core.get("last_updated"), str) and _RFC3339.match(core["last_updated"])):
        problems.append("last_updated is not an RFC 3339 date-time")
    if schema_path:
        try:
            import jsonschema
        except ImportError:
            problems.append("--openeox-schema given but jsonschema is not installed (pip install eox-scan[schema])")
        else:
            with open(schema_path) as f:
                schema = json.load(f)
            v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
            problems += [f"schema: {e.message}" for e in v.iter_errors(core)]
    return problems
