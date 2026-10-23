"""The gateway evidence successor keeps verdicts and records deciding settings."""

from test_peaso_compliance_new_sw14 import case, failure

from peaso.checks import azure_gateway_cidr_evidence_successor_20261021 as successor


def test_pass_records_the_enabled_remote_address_block_rule():
    item, index = case(successor.CHECK_ID)
    old_status = successor._ORIGINAL(item, index)[0]

    status, evidence = successor.evaluate(item, index)

    assert old_status == status == 'PASS'
    assert evidence['approved_cidrs'] == ['10.0.0.0/8']
    assert evidence['outside_approved_ranges_empty'] is False
    path, = evidence['effective_paths']
    assert path['policy_state'] == 'Enabled'
    assert path['policy_mode'] == 'Prevention'
    assert path['remote_addr_rules'][0]['action'] == 'Block'
    assert path['remote_addr_rules'][0]['priority'] == 10
    assert path['remote_addr_rules'][0]['remote_addr_matches'][0] == {
        'cidrs': ['10.0.0.0/8'], 'cidr_count': 1, 'negated': True}


def test_fail_records_earlier_allow_without_changing_verdict():
    item, index = case(successor.CHECK_ID)
    failure(successor.CHECK_ID, item, index)

    assert successor._ORIGINAL(item, index)[0] == 'FAIL'
    status, evidence = successor.evaluate(item, index)

    assert status == 'FAIL'
    path, = evidence['effective_paths']
    assert path['decision'] == 'FAIL'
    assert path['remote_addr_rules'][0]['action'] == 'Allow'
    assert path['remote_addr_rules'][0]['priority'] == 1


def test_fail_records_missing_effective_policy():
    item, index = case(successor.CHECK_ID)
    item['gatewayAssociations']['paths'][0]['effectivePolicyId'] = None

    assert successor._ORIGINAL(item, index)[0] == 'FAIL'
    status, evidence = successor.evaluate(item, index)

    assert status == 'FAIL'
    path, = evidence['effective_paths']
    assert path['effective_policy_id'] is None
    assert path['decision'] == 'FAIL'
