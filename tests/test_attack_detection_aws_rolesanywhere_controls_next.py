"""Roles Anywhere mutation signals from real, redacted CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.rolesanywhere_anchor_ca_replaced',
          'request.rolesanywhere_profile_boundary_broad',
          'request.rolesanywhere_issuer_cn_deleted',
          'request.rolesanywhere_issuer_cn_unmapped'}
RULES = tuple(Rule(id=f, title=f, description=f, level='high', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_rolesanywhere_lab_events.json').read_text())


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events, RULES)}


def test_real_mutations_match_one_rule_each():
    assert hits(EVENTS) == FIELDS
    for event in EVENTS:
        assert len(hits([event])) == 1
    fixture = json.dumps(EVENTS)
    assert 'PRIVATE KEY' not in fixture and 'SessionToken' not in fixture


def test_failed_and_unconfirmed_mutations_do_not_match():
    for event in EVENTS:
        for change in ({'errorCode': 'AccessDenied'}, {'eventCategory': 'Data'},
                       {'readOnly': True}, {'responseElements': {}}):
            assert not hits([{**event, **change}])


def test_specific_security_fields_are_required():
    by_name = {e['eventName']: e for e in EVENTS}
    profile = copy.deepcopy(by_name['UpdateProfile'])
    profile['requestParameters']['sessionPolicy'] = '{"Statement":[{"Effect":"Allow","Action":"iam:GetRole","Resource":"*"}]}'
    assert not hits([profile])
    anchor = copy.deepcopy(by_name['UpdateTrustAnchor'])
    anchor['requestParameters']['source']['sourceType'] = 'AWS_ACM_PCA'
    assert not hits([anchor])
    for name in ('DeleteAttributeMapping', 'PutAttributeMapping'):
        mapping = copy.deepcopy(by_name[name])
        mapping['responseElements']['profile']['attributeMappings'][0] = {
            'certificateField': 'x509Issuer', 'mappingRules': [{'specifier': '*'}]}
        assert not hits([mapping])
