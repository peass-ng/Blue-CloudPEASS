"""EMR Serverless detection uses a sanitized real CloudTrail event."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id='emr-runtime', title='emr-runtime', description='emr-runtime',
            level='medium', technique_id='aws-emr-serverless-spark-runtime-defaults-updated',
            product='aws', selection={'request.emr_spark_defaults_updated': True})
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_emr_serverless_lab_events.json').read_text())


def hits(event):
    return detect_aws_events([event], [RULE])


def test_accepted_spark_defaults_update_and_negative_cases():
    update, start = EVENTS
    assert [x.technique_id for x in hits(update)] == [RULE.technique_id]
    assert not hits(start)
    for change in (
        {'errorCode': 'AccessDeniedException'},
        {'eventCategory': 'Data'},
        {'readOnly': True},
        {'managementEvent': False},
        {'eventName': 'GetApplication'},
    ):
        assert not hits({**update, **change})
    missing = copy.deepcopy(update)
    missing['requestParameters']['runtimeConfiguration'] = []
    assert not hits(missing)
    wrong_class = copy.deepcopy(update)
    wrong_class['requestParameters']['runtimeConfiguration'][0]['classification'] = 'hive-site'
    assert not hits(wrong_class)
    wrong_arn = copy.deepcopy(update)
    wrong_arn['responseElements']['application']['arn'] = wrong_arn['responseElements']['application']['arn'].replace(':222233334444:', ':000000000000:')
    assert not hits(wrong_arn)
    wrong_type = copy.deepcopy(update)
    wrong_type['responseElements']['application']['type'] = 'Hive'
    assert not hits(wrong_type)
