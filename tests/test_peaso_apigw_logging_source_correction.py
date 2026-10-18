"""Hash-bound API Gateway protocol erratum preserves the signed history."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.catalog import description_for, proposal_provenance_for, full_requirements
from peaso.checks import aws_apigateway_logging_source_correction as correction

def test_original_signed_input_remains_bound_and_rejects_drift():
    row = next(r for r in full_requirements()["proposed_checks"] if r["id"] == correction.CHECK_ID)
    before = deepcopy(row)
    assert correction.validate_prior_spec(row)
    assert row == before == correction.FROZEN_SPEC
    row["predicate"] += " changed"
    with pytest.raises(ValueError, match="Historical API Gateway"):
        correction.validate_prior_spec(row)

def test_public_contract_names_protocol_and_observation_limits():
    check = next(c for c in CHECKS if c.id == correction.CHECK_ID)
    public = check.public()
    assert public["dependencies"] == ["http_api_stage", "rest_api_stage", "rest_api_method"]
    assert "WebSocket" in public["description"] and "not proof of log delivery" in public["description"]
    assert "HTTP" in public["not_applicable_when"]
    assert public["source_correction"]["source_relationship"].startswith("Derived")
    provenance = proposal_provenance_for(check.id)
    assert provenance["signed_spec_sha256"] == correction.PRIOR_FROZEN_SPEC_SHA256
    assert provenance["signed_spec_status"] == "historical_superseded_for_this_check"
    assert provenance["source_correction"] == public["source_correction"]
    assert description_for(check.id) == correction.description()

def test_v2_missing_native_logging_guard_is_hash_bound():
    assert correction.SOURCE_CORRECTION['version']=='peaso-apigateway-logging-source-correction-v2'
    assert correction.SOURCE_CORRECTION['prior_current_canonical_spec_sha256']==correction.PRIOR_CORRECTED_SPEC_SHA256
    assert correction.CORRECTED_SPEC_SHA256!=correction.PRIOR_CORRECTED_SPEC_SHA256
    assert 'missing effective INFO/ERROR' in correction.CORRECTED_SPEC['predicate']
    assert 'complete native settings map' in correction.DESCRIPTION['fail_when']
