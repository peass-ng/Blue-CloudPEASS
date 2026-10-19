"""RDS SQL logging and TLS parameter changes from a disposable live group."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events

EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_rds_parameter_replica_lab_events.json').read_text())
RULES = tuple(Rule(id=f'test-{flag}', title=flag, description=flag, level='medium',
                   technique_id=f'test-{flag}', product='aws',
                   selection={'event.name': ('DownloadDBLogFilePortion' if flag == 'rds_sql_logging_then_log_read' else 'ModifyDBParameterGroup'), 'event.outcome': 'success',
                              f'request.{flag}': True})
              for flag in ('rds_sql_logging_enabled', 'rds_tls_requirement_disabled',
                           'rds_sql_logging_then_log_read'))


def hits(events):
    return {h.rule_id for h in detect_aws_events(events, RULES)}


def event(parameter):
    return copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'ModifyDBParameterGroup'
                              and any(p['parameterName'] == parameter for p in e['requestParameters']['parameters'])))


def test_live_changes_hit_both_rules():
    assert hits(EVENTS) == {r.id for r in RULES}


def test_public_flag_request_and_private_reversal_from_same_live_instance():
    rule = Rule(id='test-public-request', title='public', description='public', level='medium',
                technique_id='test-public-request', product='aws',
                selection={'event.name': 'ModifyDBInstance', 'event.outcome': 'success',
                           'request.rds_instance_public_requested': True})
    public = next(e for e in EVENTS if e['eventName'] == 'ModifyDBInstance'
                  and e['requestParameters'].get('publiclyAccessible') is True)
    private = next(e for e in EVENTS if e['eventName'] == 'ModifyDBInstance'
                   and e['requestParameters'].get('publiclyAccessible') is False)
    assert len(detect_aws_events([public], (rule,))) == 1
    assert not detect_aws_events([private], (rule,))


def test_safe_values_and_unrelated_parameter_do_not_match():
    log = event('log_statement')
    for p in log['requestParameters']['parameters']:
        p['parameterValue'] = 'none' if p['parameterName'] == 'log_statement' else '-1'
    assert not hits([log])
    tls = event('rds.force_ssl')
    tls['requestParameters']['parameters'][0]['parameterValue'] = '1'
    assert not hits([tls])
    tls['requestParameters']['parameters'][0]['parameterName'] = 'work_mem'
    tls['requestParameters']['parameters'][0]['parameterValue'] = '0'
    assert not hits([tls])


def test_failed_or_unconfirmed_and_nonmanagement_changes_do_not_match():
    for source in (event('log_statement'), event('rds.force_ssl')):
        for key, value in (('errorCode', 'AccessDenied'), ('eventCategory', 'Data'),
                           ('managementEvent', False), ('readOnly', True)):
            changed = copy.deepcopy(source)
            changed[key] = value
            assert not hits([changed])
        changed = copy.deepcopy(source)
        changed['responseElements']['dBParameterGroupName'] = 'another-group'
        assert not hits([changed])


def test_log_read_chain_needs_matching_attachment_reboot_and_actor():
    sequence = [e for e in EVENTS if e['eventName'] in {
        'ModifyDBParameterGroup', 'ModifyDBInstance', 'RebootDBInstance',
        'DownloadDBLogFilePortion'}]
    marker = 'test-rds_sql_logging_then_log_read'
    assert marker in hits(sequence)
    for omitted in ('ModifyDBInstance', 'RebootDBInstance', 'DownloadDBLogFilePortion'):
        assert marker not in hits([e for e in sequence if e['eventName'] != omitted])
    for name, change in (
        ('ModifyDBInstance', lambda e: e['requestParameters'].update(dBParameterGroupName='other')),
        ('RebootDBInstance', lambda e: e['requestParameters'].update(dBInstanceIdentifier='other')),
        ('DownloadDBLogFilePortion', lambda e: e['userIdentity'].update(arn='arn:aws:iam::999999999999:user/other')),
        ('DownloadDBLogFilePortion', lambda e: e.update(recipientAccountId='999999999999')),
        ('DownloadDBLogFilePortion', lambda e: e.update(eventTime='2026-10-20T01:00:00Z')),
        ('DownloadDBLogFilePortion', lambda e: e.update(errorCode='AccessDenied')),
    ):
        changed = copy.deepcopy(sequence)
        targets = [e for e in changed if e['eventName'] == name]
        for target in (targets if name == 'RebootDBInstance' else targets[:1]):
            change(target)
        assert marker not in hits(changed)
