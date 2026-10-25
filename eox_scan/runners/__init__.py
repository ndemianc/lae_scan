"""Subprocess wrappers for the pinned, unmodified Syft and xeol binaries."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_LOCK = os.environ.get("EOX_TOOLS_LOCK") or (os.path.join(_ROOT, "tools.lock")
                                                    if os.path.exists(os.path.join(_ROOT, "tools.lock"))
                                                    else os.path.join(os.getcwd(), "tools.lock"))
TOOLS = ("syft", "xeol")

INSTALL_HINT = {
    "syft": "Install Syft: `brew install syft`, or see https://github.com/anchore/syft#installation",
    "xeol": "Install xeol: `brew tap xeol-io/xeol && brew install xeol`, or see "
            "https://github.com/xeol-io/xeol#installation",
}


class ToolError(RuntimeError):
    pass


def load_lock(path: Optional[str] = None) -> Dict:
    p = path or DEFAULT_LOCK
    if not os.path.exists(p):
        return {}
    with open(p) as f:
        return json.load(f)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def locate(name: str) -> Optional[str]:
    p = os.environ.get(f"EOX_{name.upper()}_BIN") or shutil.which(name)
    return os.path.realpath(p) if p else None


def version_of(path: str) -> Optional[str]:
    try:
        out = subprocess.run([path, "version"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"^Version:\s*(\S+)", out, re.M)
    return m.group(1) if m else None


def find_tool(name: str, lock: Dict, allow_unpinned: bool = False) -> str:
    """Locate a tool binary and check it against the SHA-256 pinned in tools.lock."""
    path = locate(name)
    if not path:
        raise ToolError(f"{name} not found on PATH (or set EOX_{name.upper()}_BIN). {INSTALL_HINT[name]}")
    pins = {k.lower() for k in (lock.get(name, {}).get("sha256") or {}).values()}
    if pins:
        actual = sha256_file(path)
        if actual not in pins and not allow_unpinned:
            raise ToolError(f"{name} at {path} has sha256 {actual}, which is not pinned in tools.lock. "
                            "Check it against the release checksums, then run `eox-scan tools --pin`, "
                            "or pass --allow-unpinned.")
    elif not allow_unpinned:
        raise ToolError(f"no sha256 pinned for {name} in tools.lock. Check the binary against the release "
                        "checksums, then run `eox-scan tools --pin`, or pass --allow-unpinned.")
    return path


def platform_key() -> str:
    u = os.uname()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(u.machine, u.machine)
    return f"{u.sysname.lower()}_{arch}"


def check(pin: bool = False, lock_path: Optional[str] = None) -> List[Dict]:
    """Report each tool's path, version and hash; with pin=True record them in tools.lock."""
    lock_path = lock_path or DEFAULT_LOCK
    lock = load_lock(lock_path)
    rows = []
    for name in TOOLS:
        path = locate(name)
        row = {"tool": name, "path": path, "version": None, "sha256": None, "pinned": False}
        if path:
            row["version"], row["sha256"] = version_of(path), sha256_file(path)
            pins = {k.lower() for k in (lock.get(name, {}).get("sha256") or {}).values()}
            row["pinned"] = row["sha256"] in pins
            if pin:
                entry = lock.setdefault(name, {})
                entry["version"] = row["version"]
                entry.setdefault("sha256", {})[platform_key()] = row["sha256"]
                row["pinned"] = True
        rows.append(row)
    if pin:
        with open(lock_path, "w") as f:
            json.dump(lock, f, indent=2)
            f.write("\n")
    return rows


def run(cmd: List[str], env: Optional[Dict[str, str]] = None, timeout: int = 1800) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, **(env or {})}, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise ToolError(f"{os.path.basename(cmd[0])} did not finish within {timeout}s") from None
    if proc.returncode != 0:
        raise ToolError(f"{os.path.basename(cmd[0])} exited {proc.returncode}: {proc.stderr.strip()[:2000]}")
    return proc.stdout
