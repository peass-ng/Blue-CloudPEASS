"""Configuration-only enclave controls and important policy counterexamples."""
import pytest
from peaso.checks import aws_kms_enclave_review_20261019 as kms

PCR0 = 'kms:RecipientAttestation:PCR0'
PCR3 = 'kms:RecipientAttestation:PCR3'


def allow(condition=None, **extra):
    row = {'Effect': 'Allow', 'Principal': '*', 'Action': 'kms:Decrypt', 'Resource': '*', **extra}
    if condition is not None:
        row['Condition'] = condition
    return row


def key(*statements, **extra):
    return {'KeyId': 'key-1', 'Metadata': {'KeyMetadata': {'KeyManager': 'CUSTOMER', 'KeyState': 'Enabled', 'Description': 'Nitro enclave'}},
        'Policy': {'Policy': {'Statement': list(statements)}}, 'Tags': [], 'Aliases': [], **extra}


def deny(**extra):
    return {'Effect': 'Deny', 'Principal': '*', 'Action': 'kms:*', 'Resource': '*',
        'Condition': {'Null': {PCR0: 'true'}}, **extra}


@pytest.mark.parametrize('function', [kms.enforced, kms.no_bypass, kms.deployment_binding])
def test_positive_and_negative(function):
    assert function(key(allow({'StringEquals': {PCR0: 'abc', PCR3: 'def'}})))[0] == 'PASS'
    bad = allow({'StringEquals': {PCR0: 'abc'}}) if function is kms.deployment_binding else allow()
    assert function(key(bad))[0] == 'FAIL'


@pytest.mark.parametrize('operator,value,guard,expected', [
    ('StringEquals', 'abc', False, 'PASS'), ('StringEquals', ['abc', 'def'], False, 'PASS'),
    ('StringLike', '*', False, 'FAIL'), ('StringLike', 'abc?', False, 'FAIL'),
    ('StringEqualsIfExists', 'abc', False, 'FAIL'), ('StringNotEquals', 'abc', False, 'FAIL'),
    ('ForAllValues:StringEquals', 'abc', False, 'FAIL'), ('ForAllValues:StringEquals', 'abc', True, 'PASS'),
    ('ForAnyValue:StringEquals', 'abc', False, 'PASS')])
def test_restrictive_conditions(operator, value, guard, expected):
    condition = {operator: {PCR0.lower(): value}}
    if guard:
        condition['Null'] = {PCR0: 'false'}
    assert kms.enforced(key(allow(condition)))[0] == expected


@pytest.mark.parametrize('selector', [
    {'Action': 'KMS:DECRYPT'}, {'Action': 'kms:GenerateDataKey*'}, {'Action': '*'},
    {'NotAction': ['kms:DescribeKey', 'kms:List*']}])
def test_sensitive_action_patterns_and_notaction(selector):
    row = allow()
    row.pop('Action')
    row.update(selector)
    assert kms.enforced(key(row))[0] == 'FAIL'


def test_notaction_excludes_all_sensitive_and_nonsensitive_allow():
    row = allow(NotAction='kms:*')
    row.pop('Action')
    assert kms.enforced(key(row))[0] == 'PASS'
    assert kms.enforced(key(allow(Action='kms:DescribeKey')))[0] == 'PASS'


@pytest.mark.parametrize('change', [
    {'Principal': {'AWS': ['*']}}, {'Action': 'kms:Decrypt'},
    {'Condition': {'StringNotEqualsIfExists': {PCR0: 'abc'}}}])
def test_proven_deny_variants(change):
    assert kms.no_bypass(key(allow(), deny(**change)))[0] == 'PASS'


def test_extra_deny_condition_and_resource_do_not_falsely_pass():
    conditional = deny(Condition={'Null': {PCR0: 'true'}, 'StringEquals': {'aws:SourceAccount': '111111111111'}})
    assert kms.no_bypass(key(allow(), conditional))[0] == 'UNKNOWN'
    assert kms.no_bypass(key(allow(), deny(Resource='arn:aws:kms:us-east-1:111111111111:key/other')))[0] == 'UNKNOWN'
    assert kms.no_bypass(key(allow(), deny(Principal={'AWS': 'arn:aws:iam::111111111111:role/one'})))[0] == 'UNKNOWN'


def test_deny_actions_union_and_uncovered_action():
    row = allow(Action=['kms:Decrypt', 'kms:GenerateDataKey'])
    assert kms.no_bypass(key(row, deny(Action='kms:Decrypt')))[0] == 'FAIL'
    assert kms.no_bypass(key(row, deny(Action='kms:Decrypt'), deny(Action='kms:GenerateDataKey')))[0] == 'PASS'


@pytest.mark.parametrize('pcr,expected', [('PCR0', 'FAIL'), ('PCR1', 'FAIL'), ('PCR2', 'FAIL'), ('PCR3', 'PASS'), ('PCR4', 'PASS'), ('PCR8', 'PASS')])
def test_deployment_measurements(pcr, expected):
    assert kms.deployment_binding(key(allow({'StringEquals': {'kms:RecipientAttestation:' + pcr: 'abc'}})))[0] == expected


def test_deployment_account_binding_and_no_vacuous_pass():
    assert kms.deployment_binding(key(allow()))[0] == 'UNKNOWN'
    assert kms.deployment_binding(key(allow({'StringEquals': {PCR0: 'abc', 'aws:PrincipalAccount': '111111111111'}})))[0] == 'PASS'
    assert kms.deployment_binding(key(allow({'StringEquals': {PCR0: 'abc'}, 'StringEqualsIfExists': {'aws:PrincipalAccount': '111111111111'}})))[0] == 'FAIL'


@pytest.mark.parametrize('signal', ['description', 'policy', 'tag', 'alias'])
def test_enclave_applicability_signals(signal):
    item = key(allow())
    item['Metadata']['KeyMetadata']['Description'] = 'ordinary key'
    if signal == 'description':
        item['Metadata']['KeyMetadata']['Description'] = 'ENCLAVE workload'
    elif signal == 'policy':
        item['Policy']['Policy']['Statement'][0]['Condition'] = {'StringLike': {PCR0: '*'}}
    elif signal == 'tag':
        item['Tags'] = [{'TagKey': 'prowler:enclave-key', 'TagValue': 'true'}]
    else:
        item['Aliases'] = [{'AliasName': 'alias/enclave-test'}]
    assert kms.enforced(item)[0] == 'FAIL'


def test_ordinary_keys_not_flagged_and_missing_inventory_unknown():
    item = key(allow())
    item['Metadata']['KeyMetadata']['Description'] = 'ordinary key'
    assert kms.enforced(item)[0] == 'NOT_APPLICABLE'
    item.pop('Aliases')
    assert kms.enforced(item)[0] == 'UNKNOWN'
    item['Tags'] = [{'TagKey': 'enclave', 'TagValue': 'yes'}]
    assert kms.enforced(item)[0] == 'FAIL'  # positive signal does not require negative alias proof


@pytest.mark.parametrize('marker', ['denied', 'partial', 'not_collected', 'malformed'])
def test_incomplete_policy_and_applicability_never_pass(marker):
    item = key(allow({'StringEquals': {PCR3: 'abc'}}))
    item['Policy']['collection_status'] = marker
    assert kms.enforced(item)[0] == 'UNKNOWN'
    item = key(allow())
    item['Metadata']['KeyMetadata']['Description'] = 'ordinary'
    item['_coverage'] = {'Tags': {'status': marker}}
    assert kms.enforced(item)[0] == 'UNKNOWN'


@pytest.mark.parametrize('statement', [None, {'Effect': 'Allow'}, allow(Action=[]), allow(Condition={'StringEquals': []}), allow(Action='kms:[D]ecrypt')])
def test_malformed_policy_never_passes(statement):
    assert kms.enforced(key(statement))[0] == 'UNKNOWN'


def test_aws_managed_and_disabled_not_applicable_and_specs_no_registration():
    item = key(allow())
    item['Metadata']['KeyMetadata']['KeyManager'] = 'AWS'
    assert kms.enforced(item)[0] == 'NOT_APPLICABLE'
    item['Metadata']['KeyMetadata'].update(KeyManager='CUSTOMER', KeyState='Disabled')
    assert kms.enforced(item)[0] == 'NOT_APPLICABLE'
    from peaso.checks import CHECKS
    before = {c.id for c in CHECKS}
    import importlib
    importlib.reload(kms)
    assert {c.id for c in CHECKS} == before
    assert [r['severity'] for r in kms.SPECS] == ['high', 'high', 'info']


def test_policy_variable_is_not_a_fixed_attestation_or_deployment_binding():
    assert kms.enforced(key(allow({'StringEquals': {PCR0: '${aws:PrincipalTag/pcr}'}})))[0] == 'FAIL'
    assert kms.deployment_binding(key(allow({'StringEquals': {PCR0: 'abc', 'aws:PrincipalAccount': '${aws:PrincipalTag/account}'}})))[0] == 'FAIL'
