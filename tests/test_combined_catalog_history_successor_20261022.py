"""Current metadata drift remains rejected before exact history reconstruction."""
from copy import deepcopy
import pytest
from peaso.engine import get_catalog
from tests.provider_group_catalog_history_20261021 import combined_predecessor_catalog

@pytest.fixture(scope="module")
def current_catalog():
    return get_catalog()

@pytest.mark.parametrize("tamper", ["existing_title", "new_check_removed", "top_metadata"])
def test_combined_catalog_rejects_unreviewed_metadata(current_catalog, tamper):
    value = deepcopy(current_catalog)
    if tamper == "existing_title":
        value["checks"][0]["title"] += " unreviewed"
    elif tamper == "new_check_removed":
        value["checks"].pop()
    else:
        value["framework_versions"] = {}
    with pytest.raises(AssertionError, match="Combined current catalog changed"):
        combined_predecessor_catalog(value)
