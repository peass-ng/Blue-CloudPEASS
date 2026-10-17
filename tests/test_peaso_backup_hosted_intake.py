"""Prospective hosted validation for explicit AWS Backup operator policy."""

from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from peaso.collectors.aws_policy import backup_plan_policy
from peaso.server.validation import validate_connector


SETTINGS = SimpleNamespace(auth_mode="cognito")
AUTH = {"method": "access_keys", "aws_access_key_id": "fixture-id",
        "aws_secret_access_key": "fixture-secret"}
SCOPE = "123456789012/us-east-1"


def declaration(scopes=(SCOPE,), hours=24):
    return {"compliance_policy": {"aws_backup_plan": {
        "applies_to": list(scopes), "required_frequency_hours": hours}}}


def test_explicit_scoped_declaration_is_accepted_without_auth_mutation():
    auth = dict(AUTH)
    options = declaration((SCOPE, "123456789012/eu-west-1"), 36)
    validate_connector("aws", auth, options, SETTINGS)
    assert auth == AUTH
    assert options == declaration((SCOPE, "123456789012/eu-west-1"), 36)
    assert backup_plan_policy(options) == {"status": "collected", "source": "operator-supplied",
        "basis": "operator-declared threshold; not an observed cloud fact",
        "applies_to": ["123456789012/eu-west-1", SCOPE], "required_frequency_hours": 36}


def test_absent_declaration_stays_absent_with_no_frequency_default():
    options = {}
    validate_connector("aws", dict(AUTH), options, SETTINGS)
    assert options == {} and backup_plan_policy(options) is None


@pytest.mark.parametrize("options", [
    {"compliance_policy": {}},
    {"compliance_policy": None},
    {"compliance_policy": {"unsupported": {}}},
    {"compliance_policy": {"aws_backup_plan": {"applies_to": [SCOPE]}}},
    declaration((), 24),
    declaration(("*",), 24),
    declaration((SCOPE, SCOPE), 24),
    declaration((SCOPE,), 0),
    declaration((SCOPE,), True),
    declaration((SCOPE,), 745),
])
def test_malformed_or_unsupported_declaration_is_rejected(options):
    with pytest.raises(HTTPException) as error:
        validate_connector("aws", dict(AUTH), options, SETTINGS)
    assert error.value.status_code == 422


def test_foreign_provider_cannot_supply_aws_backup_policy():
    with pytest.raises(HTTPException) as error:
        validate_connector("gcp", {"method": "token", "token": "fixture-token"},
                           declaration(), SETTINGS)
    assert error.value.status_code == 422
