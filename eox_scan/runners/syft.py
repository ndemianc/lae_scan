"""Run Syft on an image or directory and return its native JSON SBOM.

Syft JSON is used (not CycloneDX) because it carries the package metadata the
supplier resolver needs: dpkg Source, RPM Vendor and sourceRpm, apk origin.

For a bare image reference Syft first tries the Docker daemon and only then the
registry. A Docker Desktop that is installed but not running (or a credential
helper waiting for the keychain) can make that first step hang, so Syft's own
progress is shown on the terminal and the run has a timeout. Prefix the image
with `registry:` to skip the daemon entirely.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Dict, Optional

from . import ToolError, find_tool, load_lock

DEFAULT_TIMEOUT = 600
SCHEMES = ("docker:", "podman:", "registry:", "docker-archive:", "oci-archive:", "oci-dir:", "singularity:",
           "dir:", "file:")


def scan(target: str, out_path: str, lock: Optional[Dict] = None, allow_unpinned: bool = False,
         timeout: int = DEFAULT_TIMEOUT) -> Dict:
    lock = lock if lock is not None else load_lock()
    syft = find_tool("syft", lock, allow_unpinned)
    cmd = [syft, "scan", target, "-o", f"syft-json={out_path}"]
    if not sys.stderr.isatty():
        cmd.append("-q")
    env = {**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"}
    try:
        # stdout/stderr are not captured: Syft's progress goes straight to the terminal
        proc = subprocess.run(cmd, env=env, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        hint = ""
        if not target.startswith(SCHEMES) and not os.path.exists(target):
            hint = (f" For an image, Syft tries the Docker daemon first; if Docker is not running or stuck, "
                    f"pull straight from the registry instead: eox-scan scan registry:{target} ...")
        raise ToolError(f"syft did not finish within {timeout}s.{hint} "
                        f"Use --syft-timeout to allow longer.") from None
    if proc.returncode != 0:
        raise ToolError(f"syft exited {proc.returncode} (see its output above)")
    with open(out_path) as f:
        return json.load(f)
