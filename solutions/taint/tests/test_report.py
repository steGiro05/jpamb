import jvm
from jvm.state import PC

from taint_analysis import (
    AnalysisResult,
    TaintFinding,
    TaintSet,
    analysis_hints,
)


ENTRY = jvm.AbsMethodID.decode("example.Entry.run:(Ljava/lang/String;)V")
SINK = jvm.AbsMethodID.decode(
    "java.lang.Class.forName:(Ljava/lang/String;)Ljava/lang/Class;"
)


def test_report_exposes_pipeline_terms_and_parameter_hints() -> None:
    finding = TaintFinding(
        sink=SINK,
        call_site=PC(ENTRY, 4),
        labels=TaintSet.for_parameter(0),
        category="CWE-470",
        distance_to_exploit_target=2,
    )

    report = analysis_hints(ENTRY, AnalysisResult({}, (finding,)))

    assert report == {
        "entry_method": ENTRY.encode(),
        "classification": "flagged_unverified",
        "findings": [
            {
                "category": "CWE-470",
                "taint_sink": SINK.encode(),
                "call_site": PC(ENTRY, 4).encode(),
                "labels": ["p0"],
                "relevant_parameters": [0],
                "distance_to_exploit_target": 2,
            }
        ],
    }


def test_report_classifies_an_empty_result_as_unflagged() -> None:
    report = analysis_hints(ENTRY, AnalysisResult({}, ()))

    assert report["classification"] == "unflagged"
    assert report["findings"] == []
