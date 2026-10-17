"""Frozen APIM diagnostic metadata remains a prerequisite to usable tracing."""
import copy
import importlib

import pytest

from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw23",)):
    _canonical = importlib.import_module("test_peaso_compliance_new_sw23")

children = _canonical.children
fixture = _canonical.fixture
sw = _canonical.sw
_evaluate = _canonical._evaluate
SERVICE = _canonical.SERVICE
API = _canonical.API


@pytest.mark.parametrize("missing", ["sampling", "alwaysLog"])
def test_usable_route_with_unresolved_peer_diagnostic_is_unknown(missing):
    parent, evidence = fixture(sw.DIAGNOSTICS)
    peer = copy.deepcopy(evidence["apis"]["items"][0]["diagnostics"]["items"][0])
    peer["id"] = API + "/diagnostics/unresolved"
    if missing == "sampling":
        peer["properties"]["sampling"].pop("percentage")
    else:
        peer["properties"].pop("alwaysLog")
    evidence["apis"]["items"][0]["diagnostics"]["items"].append(peer)
    assert _evaluate(parent, evidence)[0] == "UNKNOWN"


def test_unmeasured_peer_credentials_do_not_hide_usable_route():
    parent, evidence = fixture(sw.DIAGNOSTICS)
    peer = copy.deepcopy(evidence["apis"]["items"][0]["diagnostics"]["items"][0])
    peer["id"] = API + "/diagnostics/unmeasured"
    peer["properties"]["loggerId"] = SERVICE + "/loggers/unmeasured"
    evidence["apis"]["items"][0]["diagnostics"]["items"].append(peer)
    logger = copy.deepcopy(evidence["loggers"]["items"][0])
    logger["id"] = peer["properties"]["loggerId"]
    logger["credentials_measured"] = False
    logger.pop("usable")
    evidence["loggers"]["items"].append(logger)
    assert _evaluate(parent, evidence)[0] == "PASS"


@pytest.mark.parametrize("missing", ["sampling", "alwaysLog"])
@pytest.mark.parametrize("missing_first", [True, False])
def test_independent_missing_diagnostic_beats_unresolved_peer_metadata(missing, missing_first):
    parent, evidence = fixture(sw.DIAGNOSTICS)
    uncertain = evidence["apis"]["items"][0]
    if missing == "sampling":
        uncertain["diagnostics"]["items"][0]["properties"]["sampling"].pop("percentage")
    else:
        uncertain["diagnostics"]["items"][0]["properties"].pop("alwaysLog")
    measured_failure = copy.deepcopy(uncertain)
    measured_failure["id"] = SERVICE + "/apis/measured-missing"
    measured_failure["diagnostics"] = children([])
    evidence["apis"] = children([measured_failure, uncertain] if missing_first else [uncertain, measured_failure])
    status, detail = _evaluate(parent, evidence)
    assert status == "FAIL"
    assert detail["rest_apis_without_usable_tracing_diagnostic"] == [measured_failure["id"]]
