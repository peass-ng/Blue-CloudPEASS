"""Final local boundary for APIM logger type uncertainty."""

import copy

from tests.test_peaso_apim_evidence_continuation import API, SERVICE, _evaluate, fixture, sw


def test_unknown_peer_logger_type_preserves_usable_same_api_route():
    parent, evidence = fixture(sw.DIAGNOSTICS)
    diagnostic = copy.deepcopy(evidence["apis"]["items"][0]["diagnostics"]["items"][0])
    diagnostic["id"] = API + "/diagnostics/unknown-logger-type"
    diagnostic["properties"]["loggerId"] = SERVICE + "/loggers/unknown-type"
    evidence["apis"]["items"][0]["diagnostics"]["items"].append(diagnostic)
    logger = copy.deepcopy(evidence["loggers"]["items"][0])
    logger["id"] = diagnostic["properties"]["loggerId"]
    logger["properties"]["loggerType"] = "unrecognized"
    evidence["loggers"]["items"].append(logger)
    assert _evaluate(parent, evidence)[0] == "PASS"
