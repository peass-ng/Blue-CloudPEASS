from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from tests.azure_native_successor_inputs_20261020 import current_cases

IDS = ["azure.claude2.vnet_flow_logs_to_log_analytics", "azure.claude2.nsg_flow_logs_to_log_analytics"]
REGISTRY = {check.id: check for check in CHECKS}


def index_for(cid, workspace, **flags):
    index = deepcopy(current_cases(cid, CASES[cid])["pass_index"])
    props = index["flow_log"][0]["data"]["properties"]
    config = props["flowAnalyticsConfiguration"]["networkWatcherFlowAnalyticsConfiguration"]
    config["workspaceId"] = workspace
    for key, value in flags.items():
        if key == "flow_enabled":
            props["enabled"] = value
        else:
            config[key] = value
    return index


@pytest.mark.parametrize("cid", IDS)
@pytest.mark.parametrize("workspace", ["", " ", True, 123, {}, []])
def test_malformed_non_null_workspace_identifier_is_unknown(cid, workspace):
    assert REGISTRY[cid].evaluate(deepcopy(CASES[cid]["pass"]), index_for(cid, workspace))[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", IDS)
def test_explicit_absence_and_disabled_collection_cannot_establish_traffic_analytics(cid):
    check = REGISTRY[cid]
    item = deepcopy(current_cases(cid, CASES[cid])["pass"])
    assert check.evaluate(item, index_for(cid, None))[0] == "FAIL"
    assert check.evaluate(item, index_for(cid, "observed-workspace", flow_enabled=False, enabled=False))[0] == "FAIL"
