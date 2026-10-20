"""SAML provider metadata replacement requires accepted IAM evidence."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id='saml-update', title='SAML metadata update', description='SAML metadata update',
            level='high', technique_id='aws-iam-saml-provider-metadata-replaced', product='aws',
            selection={'request.iam_saml_provider_metadata_replaced': True})


def hits(records):
    return detect_aws_events(records, (RULE,))


def test_real_metadata_update_and_negative_variants():
    fixture = Path(__file__).parent / 'fixtures' / 'aws_iam_saml_provider_lab_events.json'
    event = json.loads(fixture.read_text())[0]
    assert len(hits([event])) == 1
    for change in (
        lambda e: e.update(errorCode='AccessDenied'),
        lambda e: e.update(eventCategory='Data'),
        lambda e: e['requestParameters'].pop('sAMLMetadataDocument'),
        lambda e: e['responseElements'].update(sAMLProviderArn='arn:aws:iam::000000000000:saml-provider/other'),
    ):
        trial = copy.deepcopy(event)
        change(trial)
        assert not hits([trial])
    assert 'PRIVATE KEY' not in fixture.read_text()
