import pytest

import jvm
from jvm.state import PC

from taint_analysis import call_graph_from_json


ENTRY = "example.Entry.run:()V"
LEFT = "example.Helper.left:()V"
RIGHT = "example.Helper.right:()V"
TARGET = "example.Canary.<init>:()V"


def test_loader_preserves_distinct_call_sites_in_one_method() -> None:
    graph = call_graph_from_json(
        {
            "graph": {
                ENTRY: [LEFT, RIGHT],
                LEFT: [TARGET],
                RIGHT: [],
                TARGET: [],
            },
            "call_sites": [
                {
                    "caller": ENTRY,
                    "instruction_index": 2,
                    "resolved_callees": [LEFT],
                },
                {
                    "caller": ENTRY,
                    "instruction_index": 7,
                    "resolved_callees": [RIGHT],
                },
            ],
            "exploit_targets": [TARGET],
        }
    )

    entry = jvm.AbsMethodID.decode(ENTRY)
    assert graph.targets(PC(entry, 2)) == (jvm.AbsMethodID.decode(LEFT),)
    assert graph.targets(PC(entry, 7)) == (jvm.AbsMethodID.decode(RIGHT),)
    assert graph.distance(entry) == 2


def test_loader_accepts_old_sinks_name_during_transition() -> None:
    graph = call_graph_from_json(
        {
            "graph": {ENTRY: [TARGET], TARGET: []},
            "call_sites": [],
            "sinks": [TARGET],
        }
    )

    assert graph.distance(jvm.AbsMethodID.decode(ENTRY)) == 1


def test_loader_rejects_duplicate_call_sites() -> None:
    site = {
        "caller": ENTRY,
        "instruction_index": 2,
        "resolved_callees": [LEFT],
    }
    with pytest.raises(ValueError, match="duplicate call-site"):
        call_graph_from_json(
            {
                "graph": {ENTRY: [LEFT], LEFT: []},
                "call_sites": [site, site],
                "exploit_targets": [LEFT],
            }
        )
