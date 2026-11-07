"""Stable JSON-compatible hints produced for later pipeline stages."""

from typing import Any

import jvm

from taint_analysis.analyzer import AnalysisResult
from taint_analysis.summaries import TaintFinding


def finding_hint(finding: TaintFinding) -> dict[str, Any]:
    """Convert one internal finding into the shared pipeline vocabulary."""

    return {
        "category": finding.category,
        "taint_sink": finding.sink.encode(),
        "call_site": finding.call_site.encode(),
        "labels": [str(label) for label in sorted(finding.labels.labels)],
        "relevant_parameters": list(finding.relevant_parameters),
        "distance_to_exploit_target": finding.distance_to_exploit_target,
    }


def analysis_hints(
    entry_method: jvm.AbsMethodID,
    result: AnalysisResult,
) -> dict[str, Any]:
    """Serialize the static result without exposing abstract interpreter state."""

    findings = [finding_hint(finding) for finding in result.findings]
    return {
        "entry_method": entry_method.encode(),
        "classification": "flagged_unverified" if findings else "unflagged",
        "findings": findings,
    }
