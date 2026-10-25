import os

import pytest
from conftest import ROOT

from eox_scan import replay

# Paper, Table "replay" (results/results.json): (tp, fp, fn, tn)
PAPER = {
    "primary": {
        "fix_status": {"B1": (23, 0, 26, 4), "B2": (23, 0, 26, 4), "F_today": (42, 0, 7, 4), "F_full": (49, 0, 0, 4)},
        "remediability": {"B1": (29, 0, 23, 3), "B2": (29, 0, 23, 3), "F_today": (45, 0, 7, 3),
                          "F_full": (52, 0, 0, 3)},
        "classes": {"E0": 22, "E1": 10, "E2": 6, "D+": 23},
    },
    "with_derived": {
        "fix_status": {"B1": (33, 0, 26, 4), "B2": (33, 0, 26, 4), "F_today": (52, 0, 7, 4), "F_full": (59, 0, 0, 4)},
        "remediability": {"B1": (39, 0, 23, 3), "B2": (39, 0, 23, 3), "F_today": (55, 0, 7, 3),
                          "F_full": (62, 0, 0, 3)},
        "classes": {"E0": 31, "E1": 11, "E2": 6, "D+": 23},
    },
}


@pytest.fixture(scope="module")
def result(snap, event):
    return replay.run(os.path.join(ROOT, "replay", "php2shell.cdx.json"),
                      os.path.join(ROOT, "replay", "ground_truth.csv"), snap, event)


@pytest.mark.parametrize("pop", ["primary", "with_derived"])
def test_replay_reproduces_paper(result, pop):
    got = result[pop]
    assert got["build_classes"] == PAPER[pop]["classes"]
    for task in ("fix_status", "remediability"):
        for pred, want in PAPER[pop][task].items():
            m = got[task][pred]
            assert (m["tp"], m["fp"], m["fn"], m["tn"]) == want, (pop, task, pred)


def test_xeol_fail_open_is_visible(result):
    v = result["primary"]["b2_xeol_verdicts"]
    assert v.get("parse_error", 0) == 8   # RHEL '_' and '+module' releases, Ubuntu '+esm'


def test_replay_from_built_snapshot_is_identical(result, built_snapshot, event):
    from eox_scan.snapshot import Snapshot
    again = replay.run(os.path.join(ROOT, "replay", "php2shell.cdx.json"),
                       os.path.join(ROOT, "replay", "ground_truth.csv"), Snapshot.load(built_snapshot), event)
    assert again["primary"] == result["primary"]
