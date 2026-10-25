import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from eox_scan import events  # noqa: E402
from eox_scan.snapshot import Snapshot  # noqa: E402

SRC = os.path.join(ROOT, "data", "snapshot-2026-10-22")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


@pytest.fixture(scope="session")
def snap():
    return Snapshot.load(SRC)


@pytest.fixture(scope="session")
def event():
    return events.get("PHP2Shell")


@pytest.fixture(scope="session")
def built_snapshot(tmp_path_factory):
    from eox_scan.snapshot.build import build
    out = str(tmp_path_factory.mktemp("snapshot"))
    build(SRC, out, "2026-10-22")
    return out
