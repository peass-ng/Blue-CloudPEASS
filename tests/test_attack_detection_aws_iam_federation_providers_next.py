"""IAM federation provider writes from redacted CloudTrail records."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.iam_oidc_provider_created', 'request.iam_saml_provider_created',
          'request.iam_oidc_client_id_added', 'request.iam_oidc_thumbprints_updated'}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_iam_federation_provider_lab_events.json').read_text())


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_real_provider_writes_match_one_rule_each():
    assert hits(EVENTS) == FIELDS
    for event in EVENTS:
        assert len(hits([event])) == 1
    assert 'PRIVATE KEY' not in json.dumps(EVENTS)


def test_failed_and_invalid_provider_writes_are_negative():
    for event in EVENTS:
        assert not hits([{**event, 'errorCode': 'AccessDenied'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
    by_name = {event['eventName']: event for event in EVENTS}
    create_oidc = copy.deepcopy(by_name['CreateOpenIDConnectProvider'])
    create_oidc['responseElements']['openIDConnectProviderArn'] = 'arn:aws:iam::000000000000:oidc-provider/other'
    assert not hits([create_oidc])
    create_saml = copy.deepcopy(by_name['CreateSAMLProvider'])
    create_saml['requestParameters']['sAMLMetadataDocument'] = ''
    assert not hits([create_saml])
    add_client = copy.deepcopy(by_name['AddClientIDToOpenIDConnectProvider'])
    add_client['requestParameters']['clientID'] = ''
    assert not hits([add_client])
    thumb = copy.deepcopy(by_name['UpdateOpenIDConnectProviderThumbprint'])
    thumb['requestParameters']['thumbprintList'] = ['not-a-thumbprint']
    assert not hits([thumb])
