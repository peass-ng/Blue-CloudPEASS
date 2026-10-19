"""Federation deletion detections use accepted IAM events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.iam_oidc_client_id_removed', 'request.iam_oidc_provider_deleted',
          'request.iam_saml_provider_deleted'}
RULES = tuple(Rule(id=f, title=f, description=f, level='high', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_iam_federation_deletion_lab_events.json').read_text())


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_real_deletions_and_negative_variants():
    assert hits(EVENTS) == FIELDS
    for event in EVENTS:
        assert len(hits([event])) == 1
        assert not hits([{**event, 'errorCode': 'AccessDenied'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
    audience = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'RemoveClientIDFromOpenIDConnectProvider'))
    audience['requestParameters']['clientID'] = ''
    assert not hits([audience])
    oidc = copy.deepcopy(next(e for e in EVENTS if e['eventName'] == 'DeleteOpenIDConnectProvider'))
    oidc['requestParameters']['openIDConnectProviderArn'] = 'arn:aws:iam::000000000000:oidc-provider/other'
    assert not hits([oidc])
