"""Conservation witnesses catch opaque-owner field and container mutation."""
import pytest
from peaso import azure_function_package_index_20261020 as owner
from tests.case_state_contract_20261020 import case_copy, case_state

@pytest.mark.parametrize("kind", [owner._Admitted, owner._Assertions])
@pytest.mark.parametrize("field", ["snapshot", "expected", "scope", "ordinary", "identity"])
def test_preserved_identity_and_mutation_detection(kind, field):
    admitted = kind({"items": [1]}, {"status": "PASS"}, {"scope": ["one"]})
    source = {"owner": admitted, "ordinary": [1]}
    copied, before = case_copy(source), case_state(source)
    assert copied == source and copied is not source
    assert copied["owner"] is admitted
    assert copied["ordinary"] is not source["ordinary"]
    assert case_state(copied) == before
    if field == "identity":
        source["owner"] = kind(admitted.snapshot, admitted.expected, admitted.scope)
    elif field == "ordinary":
        source["ordinary"].append(2)
    else:
        getattr(admitted, field)["changed"] = True
    assert case_state(source) != before
