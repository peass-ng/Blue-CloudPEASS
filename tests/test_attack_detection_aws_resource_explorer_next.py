"""Resource Explorer view writes are detected from real, sanitized CloudTrail events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import Rule, detect_aws_events


FIELDS = {'request.resource_explorer_view_updated',
          'request.resource_explorer_default_associated',
          'request.resource_explorer_view_deleted'}
RULES = tuple(Rule(id=f, title=f, description=f, level='medium', technique_id=f,
                   product='aws', selection={f: True}) for f in FIELDS)
EVENTS = json.loads((Path(__file__).parent / 'fixtures' / 'aws_resource_explorer_lab_events.json').read_text())


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records, RULES)}


def test_accepted_view_writes_and_safe_negatives():
    assert hits(EVENTS) == FIELDS
    for event in EVENTS:
        if event['eventName'] not in {'UpdateView', 'AssociateDefaultView', 'DeleteView'}:
            assert not hits([event])
            continue
        assert len(hits([event])) == 1
        assert not hits([{**event, 'errorCode': 'AccessDeniedException'}])
        assert not hits([{**event, 'eventCategory': 'Data'}])
        assert not hits([{**event, 'readOnly': True}])
        wrong = copy.deepcopy(event)
        wrong['requestParameters']['ViewArn'] = wrong['requestParameters']['ViewArn'].replace(
            ':222233334444:', ':000000000000:')
        assert not hits([wrong])
        mismatched = copy.deepcopy(event)
        if event['eventName'] == 'UpdateView':
            mismatched['responseElements']['View']['ViewArn'] = 'arn:aws:resource-explorer-2:us-east-2:222233334444:view/other/other'
        else:
            mismatched['responseElements']['ViewArn'] = 'arn:aws:resource-explorer-2:us-east-2:222233334444:view/other/other'
        assert not hits([mismatched])
