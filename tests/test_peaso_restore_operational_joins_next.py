"""Offline SW16 operational export joins for the scoped specification policy."""

import copy
import json
from pathlib import Path

from peaso.checks import evaluate_check

CID = "azure_c5_ops_05_04ac"
FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"


def _index():
    return copy.deepcopy(json.loads(FIXTURE.read_text())[CID]["pass_index"])


def test_unrelated_specification_event_does_not_certify_required_specification_window():
    index = _index()
    for export in (index["collections"]["operational_deviation_evidence"][0]["items"][0],
                   index["operational_deviation_evidence"][0]["data"]):
        export["detectedSpecificationIds"].append("unrelated-specification")
        export["events"][0]["specificationId"] = "unrelated-specification"
    assert evaluate_check(CID, {}, index)[0] == "UNKNOWN"


def test_required_specification_event_remains_eligible():
    assert evaluate_check(CID, {}, _index())[0] == "PASS"


def test_unrelated_event_does_not_change_required_event_verdict():
    index = _index()
    for export in (index["collections"]["operational_deviation_evidence"][0]["items"][0],
                   index["operational_deviation_evidence"][0]["data"]):
        export["detectedSpecificationIds"].append("unrelated-specification")
        unrelated = copy.deepcopy(export["events"][0])
        unrelated.update(id="unrelated-deviation", specificationId="unrelated-specification",
                         delivered=False, assessed=False)
        export["events"].append(unrelated)
    assert evaluate_check(CID, {}, index)[0] == "PASS"
