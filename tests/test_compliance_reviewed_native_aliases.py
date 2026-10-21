"""Retired native metadata may satisfy historical links without becoming runnable."""
from copy import deepcopy

import pytest

from scripts.peaso_compliance_compile import historical_alias_metadata, REVIEWED_NATIVE_ALIASES_20261021


@pytest.mark.parametrize('retired,survivor', list(REVIEWED_NATIVE_ALIASES_20261021.items()))
def test_exact_reviewed_alias_retains_signed_metadata_without_mutating_live_catalog(retired, survivor):
    prior = {'id': retired, 'provider': retired.split('.')[0], 'kind': 'fixture',
             'target': 'resource', 'severity': 'high', 'category': 'exposure', 'title': 'Historical criterion'}
    current = {'id': survivor, 'provider': prior['provider'], 'type': 'fixture', 'target': 'resource'}
    indexed, native = {retired: prior}, {survivor: current}
    original = deepcopy(native)
    restored = historical_alias_metadata(indexed, native, {retired: survivor})
    assert restored == {retired: {**prior, 'type': 'fixture'}}
    assert native == original and retired not in native
    assert prior == indexed[retired] and 'type' not in prior


@pytest.mark.parametrize('mutation', ['provider', 'type', 'target', 'survivor', 'wrong_alias'])
def test_reviewed_alias_cannot_borrow_an_unrelated_or_missing_contract(mutation):
    retired, survivor = next(iter(REVIEWED_NATIVE_ALIASES_20261021.items()))
    indexed = {retired: {'id': retired, 'provider': 'aws', 'kind': 'iam_role', 'target': 'resource'}}
    native = {survivor: {'id': survivor, 'provider': 'aws', 'type': 'iam_role', 'target': 'resource'}}
    aliases = {retired: survivor}
    if mutation in ('provider', 'type', 'target'):
        native[survivor][mutation] = 'other'
    elif mutation == 'survivor':
        native = {}
    else:
        aliases[retired] = 'aws.unreviewed.survivor'
    with pytest.raises(ValueError, match='Reviewed native alias'):
        historical_alias_metadata(indexed, native, aliases)


def test_unreviewed_alias_is_not_admitted_from_name_or_catalog_text():
    assert historical_alias_metadata({'aws.other': {'kind': 'bucket'}}, {}, {'aws.other': 'aws.survivor'}) == {}


def test_reviewed_cloudwatch_scope_to_account_projection_is_explicit():
    retired = 'aws.a.cloudwatch.cross_account_role_absent'
    survivor = REVIEWED_NATIVE_ALIASES_20261021[retired]
    indexed = {retired: {'id': retired, 'provider': 'aws', 'kind': 'aws_account', 'target': 'scope'}}
    native = {survivor: {'id': survivor, 'provider': 'aws', 'type': 'aws_account', 'target': 'resource'}}
    retained = historical_alias_metadata(indexed, native, {retired: survivor})
    assert retained[retired]['target'] == 'scope'
    assert native[survivor]['target'] == 'resource'
