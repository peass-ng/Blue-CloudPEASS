"""Hosted intake contract for explicit GCP Data Access required principals."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
from peaso.server.validation import validate_connector

SETTINGS = SimpleNamespace(auth_mode='cognito')
AUTH = {'method': 'token', 'token': 'fixture-token'}
POLICY = [{'status': 'approved', 'scope': 'projects/fixture',
           'service': 'spanner.googleapis.com', 'source_ref': 'owner-approved-fixture',
           'principals': ['user:auditor@example.test']}]


def test_exact_approved_declaration_is_accepted_without_mutation():
    options = {OPTION: deepcopy(POLICY)}
    validate_connector('gcp', dict(AUTH), options, SETTINGS)
    assert options[OPTION] == POLICY
    assert normalize_owner_policy(options[OPTION], ['projects/fixture']) == POLICY


def test_absent_declaration_does_not_create_required_principals():
    options = {}
    validate_connector('gcp', dict(AUTH), options, SETTINGS)
    assert options == {}


@pytest.mark.parametrize('principal', ['user:', 'serviceAccount:', 'user:alice@',
                                        'serviceAccount:alice\t@example.test'])
def test_malformed_direct_principal_is_rejected(principal):
    options = {OPTION: deepcopy(POLICY)}
    options[OPTION][0]['principals'] = [principal]
    with pytest.raises(HTTPException) as error:
        validate_connector('gcp', dict(AUTH), options, SETTINGS)
    assert error.value.status_code == 422


@pytest.mark.parametrize('provider', ['aws', 'azure', 'k8s'])
def test_foreign_provider_rejects_gcp_declaration(provider):
    with pytest.raises(HTTPException) as error:
        validate_connector(provider, {}, {OPTION: deepcopy(POLICY)}, SETTINGS)
    assert error.value.status_code == 422


def test_duplicate_or_unapproved_declaration_is_rejected():
    for rows in (POLICY + POLICY, [{**POLICY[0], 'status': 'draft'}]):
        with pytest.raises(HTTPException) as error:
            validate_connector('gcp', dict(AUTH), {OPTION: deepcopy(rows)}, SETTINGS)
        assert error.value.status_code == 422
