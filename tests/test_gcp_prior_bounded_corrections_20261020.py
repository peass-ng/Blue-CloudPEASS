"""Native BigQuery principal and bounded WIF condition regression proofs.

The reused finite fake transport asserts exact GET URLs and native detail
projection; all socket/DNS and default/CLI authentication paths are blocked.
Historical CASES and source receipts are deliberately not rewritten.
"""
from copy import deepcopy

import pytest

from peaso.engine import evaluate_snapshot
from tests.test_gcp_metadata_final_batch_review_20261020 import forbid_network_auth
from tests.test_gcp_prior_bounded_recheck_20261020 import collect_native_service

GMAIL = 'gcp.claude.bigquery_dataset.no_gmail_access'
GROUPS = 'gcp.claude.bigquery_dataset.no_googlegroups_access'
WIF = 'gcp.claude.workload_identity_provider.multi_tenant_condition'
GITHUB = 'https://token.actions.githubusercontent.com'


def findings(kind, native, cid, *, denied=False):
    before = deepcopy(native)
    captured, transport = collect_native_service(kind, native, denied=denied)
    original = deepcopy(captured)
    rows = evaluate_snapshot(captured, checks=[cid])['findings']
    assert captured == original and native == before
    assert transport.requests and all(request['method'] == 'GET' for request in transport.requests)
    return rows


DATASETS = [
    ('gmail', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'operator@gmail.com'}]}, 'FAIL'),
    ('unrelated-suffix', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'operator@notgmail.com'}]}, 'PASS'),
    ('subdomain', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'operator@mail.gmail.com'}]}, 'PASS'),
    ('case', GMAIL, {'access': [{'role': 'WRITER', 'userByEmail': 'Operator@GMAIL.COM'}]}, 'FAIL'),
    ('plus-tag', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'operator+tag@gmail.com'}]}, 'FAIL'),
    ('native-group', GROUPS, {'access': [{'role': 'READER', 'groupByEmail': 'operators@googlegroups.com'}]}, 'FAIL'),
    ('group-suffix', GROUPS, {'access': [{'role': 'READER', 'groupByEmail': 'operators@notgooglegroups.com'}]}, 'PASS'),
    ('group-case', GROUPS, {'access': [{'role': 'OWNER', 'groupByEmail': 'Operators@GOOGLEGROUPS.COM'}]}, 'FAIL'),
    ('corporate-user', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'operator@corp.example'}]}, 'PASS'),
    ('corporate-group', GROUPS, {'access': [{'role': 'READER', 'groupByEmail': 'operators@corp.example'}]}, 'PASS'),
    ('full-empty', GMAIL, {'access': []}, 'PASS'),
    ('full-omitted', GROUPS, {}, 'PASS'),
    ('malformed-mailbox', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'agmail.com'}]}, 'UNKNOWN'),
    ('malformed-group-mailbox', GROUPS, {'access': [{'role': 'READER', 'groupByEmail': 'agooglegroups.com'}]}, 'UNKNOWN'),
    ('malformed-user-type', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 7}]}, 'UNKNOWN'),
    ('malformed-group-type', GROUPS, {'access': [{'role': 'READER', 'groupByEmail': None}]}, 'UNKNOWN'),
    ('empty-local', GMAIL, {'access': [{'role': 'READER', 'userByEmail': '@gmail.com'}]}, 'UNKNOWN'),
    ('extra-at', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'operator@team@gmail.com'}]}, 'UNKNOWN'),
    ('trailing-dot', GMAIL, {'access': [{'role': 'READER', 'userByEmail': 'operator@gmail.com.'}]}, 'UNKNOWN'),
    ('empty-label', GROUPS, {'access': [{'role': 'READER', 'groupByEmail': 'operators@corp..example'}]}, 'UNKNOWN'),
    ('whitespace', GMAIL, {'access': [{'role': 'READER', 'userByEmail': ' operator@gmail.com'}]}, 'UNKNOWN'),
    ('conflicting-principal', GROUPS, {'access': [{'role': 'READER', 'userByEmail': 'operator@corp.example', 'groupByEmail': 'operators@corp.example'}]}, 'UNKNOWN'),
    ('missing-role', GMAIL, {'access': [{'userByEmail': 'operator@corp.example'}]}, 'UNKNOWN'),
    ('denied-role', GROUPS, {'access': [{'role': 'READER', 'groupByEmail': 'operators@corp.example', '_coverage': {'role': {'status': 'denied'}}}]}, 'UNKNOWN'),
    ('denied-access', GMAIL, {'access': [], '_coverage': {'access': {'status': 'denied'}}}, 'UNKNOWN'),
    ('denied-user', GMAIL, {'access': [{'role': 'READER', '_coverage': {'userByEmail': {'status': 'denied'}}}]}, 'UNKNOWN'),
    ('denied-group', GROUPS, {'access': [{'role': 'READER', 'userByEmail': 'operator@corp.example', '_coverage': {'groupByEmail': {'status': 'denied'}}}]}, 'UNKNOWN'),
]


@pytest.mark.parametrize('label,cid,native,expected', DATASETS, ids=[row[0] for row in DATASETS])
def test_native_dataset_mailbox_domain_and_principal(label, cid, native, expected):
    rows = findings('bigquery_dataset', native, cid)
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


CONDITIONS = [
    ('owner', "assertion.repository_owner == 'review-owner'", 'PASS'),
    ('owner-id', 'assertion.repository_owner_id == "1342004"', 'PASS'),
    ('repository', "assertion.repository == 'review-owner/review-repo'", 'PASS'),
    ('nested', "((assertion.repository_owner == 'review-owner'))", 'PASS'),
    ('and-branch', "assertion.repository_owner == 'review-owner' && assertion.ref == 'refs/heads/main'", 'PASS'),
    ('two-bounded-branches', "assertion.repository_owner == 'team-one' || assertion.repository_owner_id == '1342004'", 'PASS'),
    ('true-and-owner', "true && assertion.repository_owner == 'review-owner'", 'PASS'),
    ('owner-or-false', "assertion.repository_owner == 'review-owner' || false", 'PASS'),
    ('true', 'true', 'FAIL'),
    ('or-true', "assertion.repository_owner == 'review-owner' || true", 'FAIL'),
    ('true-or', "true || assertion.repository_owner == 'review-owner'", 'FAIL'),
    ('precedence', "assertion.repository_owner == 'review-owner' && false || true", 'FAIL'),
    ('nested-tautology', "(assertion.repository_owner == 'review-owner' || (false || true))", 'FAIL'),
    ('missing', '', 'FAIL'),
    ('blank', '   ', 'FAIL'),
    ('deny-all', 'false', 'UNKNOWN'),
    ('branch-is-not-tenant', "assertion.ref == 'refs/heads/main'", 'UNKNOWN'),
    ('unbounded-branch', "assertion.repository_owner == 'review-owner' || assertion.ref == 'refs/heads/main'", 'UNKNOWN'),
    ('unsupported-function', "assertion.repository_owner.startsWith('review-')", 'UNKNOWN'),
    ('substring-literal', "'assertion.repository_owner == review-owner' == 'text'", 'UNKNOWN'),
    ('unsupported-mapped-attribute', "attribute.repository_owner == 'review-owner'", 'UNKNOWN'),
    ('unsupported-not-equal', "assertion.repository_owner != 'other-owner'", 'UNKNOWN'),
    ('empty-tenant', "assertion.repository_owner == ''", 'UNKNOWN'),
    ('wildcard', "assertion.repository_owner == '*'", 'UNKNOWN'),
    ('trailing-input', "assertion.repository_owner == 'review-owner' garbage", 'UNKNOWN'),
    ('bad-boolean', 'true ||', 'UNKNOWN'),
    ('deep', '(' * 18 + "assertion.repository_owner == 'review-owner'" + ')' * 18, 'UNKNOWN'),
    ('oversized', ' ' * 4097 + 'true', 'UNKNOWN'),
]


@pytest.mark.parametrize('label,condition,expected', CONDITIONS, ids=[row[0] for row in CONDITIONS])
def test_native_wif_bounded_condition_grammar(label, condition, expected):
    rows = findings('workload_identity_provider', {'oidc': {'issuerUri': GITHUB}, 'attributeCondition': condition}, WIF)
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


@pytest.mark.parametrize('issuer,condition,expected', [
    ('https://gitlab.com', "assertion.namespace_id == '123456'", 'PASS'),
    ('https://app.terraform.io', "assertion.terraform_organization_id == 'org-review'", 'PASS'),
    ('https://accounts.google.com', "assertion.hd == 'corp.example'", 'PASS'),
    ('https://gitlab.com', "assertion.repository_owner == 'review-owner'", 'UNKNOWN'),
    ('https://issuer.corp.example', '', 'PASS'),
    ('http://token.actions.githubusercontent.com', "assertion.repository_owner == 'review-owner'", 'UNKNOWN'),
    ('https://token.actions.githubusercontent.com@issuer.corp.example', '', 'UNKNOWN'),
    ('https://token.actions.githubusercontent.com?issuer=corp', 'true', 'UNKNOWN'),
    ('not-a-url', 'true', 'UNKNOWN'),
])
def test_native_wif_issuer_specific_tenant_claims(issuer, condition, expected):
    rows = findings('workload_identity_provider', {'oidc': {'issuerUri': issuer}, 'attributeCondition': condition}, WIF)
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


@pytest.mark.parametrize('native,expected', [
    ({'oidc': {'issuerUri': GITHUB}}, 'FAIL'),
    ({'oidc': {'issuerUri': GITHUB}, 'attributeCondition': None}, 'UNKNOWN'),
    ({'oidc': {'issuerUri': GITHUB}, 'attributeCondition': 3}, 'UNKNOWN'),
    ({'oidc': {'issuerUri': GITHUB}, '_coverage': {'attributeCondition': {'status': 'denied'}}}, 'UNKNOWN'),
    ({'oidc': {'issuerUri': GITHUB}, '_coverage': {'state': {'status': 'denied'}}}, 'UNKNOWN'),
    ({'oidc': {'_coverage': {'issuerUri': {'status': 'denied'}}}}, 'UNKNOWN'),
    ({'state': 'FUTURE_STATE', 'oidc': {'issuerUri': GITHUB}}, 'UNKNOWN'),
    ({'disabled': True, 'oidc': {'issuerUri': GITHUB}}, 'NOT_APPLICABLE'),
    ({'state': 'DELETED', 'oidc': {'issuerUri': GITHUB}}, 'NOT_APPLICABLE'),
    ({'oidc': None}, 'UNKNOWN'),
])
def test_native_wif_missing_denied_state_and_applicability(native, expected):
    rows = findings('workload_identity_provider', native, WIF)
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


@pytest.mark.parametrize('kind,cid', [('bigquery_dataset', GMAIL), ('bigquery_dataset', GROUPS), ('workload_identity_provider', WIF)])
def test_native_service_read_denial_cannot_pass(kind, cid):
    rows = findings(kind, {}, cid, denied=True)
    assert rows and all(row['status'] in ('UNKNOWN', 'DENIED') for row in rows), rows
