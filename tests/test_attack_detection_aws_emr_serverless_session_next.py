"""Cross-principal Spark Connect endpoint read from sanitized CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id='emr-session-cross-actor', title='emr-session-cross-actor',
            description='emr-session-cross-actor', level='medium',
            technique_id='aws-emr-serverless-session-endpoint-cross-actor',
            product='aws', selection={'request.emr_session_endpoint_cross_actor': True})
START, READ = json.loads((Path(__file__).parent / 'fixtures' /
                          'aws_emr_serverless_session_lab_events.json').read_text())


def hits(records):
    return detect_aws_events(records, [RULE])


def test_different_principal_reads_known_session_endpoint():
    assert [x.event_id for x in hits([READ, START])] == [READ['eventID']]
    assert not hits([READ])
    assert not hits([START])
    same_actor = copy.deepcopy(READ)
    same_actor['userIdentity'] = START['userIdentity']
    assert not hits([START, same_actor])
    same_role_other_session = copy.deepcopy(START)
    same_role_other_session['userIdentity'] = copy.deepcopy(READ['userIdentity'])
    assert not hits([same_role_other_session, READ])
    for change in (
        {'errorCode': 'AccessDeniedException'},
        {'eventCategory': 'Data'},
        {'readOnly': False},
        {'managementEvent': False},
    ):
        assert not hits([START, {**READ, **change}])
    wrong_session = copy.deepcopy(READ)
    wrong_session['requestParameters']['sessionId'] = 'other'
    assert not hits([START, wrong_session])
    wrong_app = copy.deepcopy(READ)
    wrong_app['requestParameters']['applicationId'] = 'other'
    assert not hits([START, wrong_app])
    missing_response = copy.deepcopy(START)
    missing_response['responseElements'] = None
    assert not hits([missing_response, READ])
    wrong_response = copy.deepcopy(START)
    wrong_response['responseElements']['arn'] += 'other'
    assert not hits([wrong_response, READ])
    too_late = copy.deepcopy(READ)
    too_late['eventTime'] = '2026-10-21T17:50:27Z'
    assert not hits([START, too_late])
    too_early = copy.deepcopy(READ)
    too_early['eventTime'] = '2026-10-19T17:40:27Z'
    assert not hits([START, too_early])
