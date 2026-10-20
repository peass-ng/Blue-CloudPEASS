"""RDS managed master secret read by a limited IAM role in a live lab."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_rds_proxy_master_secret_lab_events.json').read_text())
RULE = Rule(id='test-rds-managed-secret-read', title='read', description='read', level='medium',
            technique_id='test-rds-managed-secret-read', product='aws',
            selection={'event.name': 'GetSecretValue', 'event.outcome': 'success',
                       'request.rds_managed_master_secret_read': True})
PROXY_RULE = Rule(id='test-rds-proxy-secret-read', title='proxy read', description='proxy read',
                  level='medium', technique_id='test-rds-proxy-secret-read', product='aws',
                  selection={'event.name': 'GetSecretValue', 'event.outcome': 'success',
                             'request.rds_proxy_auth_secret_read_after_configuration': True})


def hits(events):
    return detect_aws_events(events, (RULE,))


def proxy_hits(events):
    return detect_aws_events(events, (PROXY_RULE,))


def read_event():
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'GetSecretValue'))


def test_limited_role_read_hits_without_secret_value_in_fixture():
    result = hits(EVENTS)
    assert len(result) == 2
    assert {h.rule_id for h in result} == {RULE.id}
    assert all('SecretString' not in json.dumps(e) for e in EVENTS)


def test_other_secrets_failed_calls_and_service_principals_are_negative():
    source = read_event()
    for change in (
        lambda e: e['requestParameters'].update(secretId='arn:aws:secretsmanager:us-east-1:222233334444:secret:ordinary-ABC123'),
        lambda e: e['requestParameters'].update(secretId=e['requestParameters']['secretId'].replace(':222233334444:', ':999999999999:')),
        lambda e: e.update(awsRegion='us-west-2'),
        lambda e: e['userIdentity'].update(type='AWSService'),
        lambda e: e.update(errorCode='AccessDenied'),
        lambda e: e.update(eventCategory='Data'),
        lambda e: e.update(managementEvent=False),
        lambda e: e.update(readOnly=False),
    ):
        changed = copy.deepcopy(source)
        change(changed)
        assert not hits([changed])


def test_metadata_enumeration_alone_is_not_a_secret_read():
    assert not hits([e for e in EVENTS if e['eventName'] != 'GetSecretValue'])


def test_recent_proxy_auth_secret_read_requires_matching_configuration():
    configured = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'CreateDBProxy'))
    reads = [copy.deepcopy(e) for e in EVENTS if e['eventName'] == 'GetSecretValue']
    assert len(proxy_hits([configured, *reads])) == 2
    assert not proxy_hits(reads)
    for change in (
        lambda e: e['requestParameters']['auth'][0].update(secretArn='arn:aws:secretsmanager:us-east-1:222233334444:secret:other-ABC123'),
        lambda e: e.update(recipientAccountId='999999999999'),
        lambda e: e.update(errorCode='AccessDenied'),
        lambda e: e.update(eventTime='2026-10-17T00:00:00Z'),
    ):
        changed = copy.deepcopy(configured)
        change(changed)
        assert not proxy_hits([changed, *reads])
    changed = copy.deepcopy(reads[0])
    changed['requestParameters']['secretId'] = 'arn:aws:secretsmanager:us-east-1:222233334444:secret:other-ABC123'
    assert len(proxy_hits([configured, changed, reads[1]])) == 1
    changed = copy.deepcopy(reads[0])
    changed['errorCode'] = 'AccessDenied'
    assert len(proxy_hits([configured, changed, reads[1]])) == 1
