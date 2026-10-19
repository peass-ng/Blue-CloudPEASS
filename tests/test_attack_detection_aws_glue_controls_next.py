"""Glue control facts require successful, specific management events."""

from copy import deepcopy
import json
from peaso.attack_detection import Rule, detect_aws_events


CASES = (
    ('GetConnection', 'aws-glue-read-connection-credentials', 'request.glue_connection_password_visible_read'),
    ('UpdateTable', 'aws-glue-poison-table-location', 'request.glue_table_location_skip_archive'),
    ('UpdateJob', 'aws-glue-update-job-script', 'request.glue_job_script_set'),
    ('CreateTrigger', 'aws-glue-recurring-job-trigger', 'request.glue_scheduled_job_trigger_activated'),
    ('PutResourcePolicy', 'aws-glue-external-catalog-resource-policy', 'request.glue_external_catalog_grant'),
)
RULES = tuple(Rule(id=str(i), title=technique, level='medium', description=technique,
                   technique_id=technique, product='aws', selection={
                       'event.source': 'glue.amazonaws.com', 'event.name': name,
                       'event.outcome': 'success', field: True})
              for i, (name, technique, field) in enumerate(CASES))


def event(name, request, read=False):
    return {'eventSource': 'glue.amazonaws.com', 'eventName': name,
            'eventCategory': 'Management', 'eventType': 'AwsApiCall',
            'managementEvent': True, 'readOnly': read,
            'recipientAccountId': '222233334444', 'requestParameters': request,
            'responseElements': None}


def hits(item):
    return {h.technique_id for h in detect_aws_events([item], RULES)}


def test_positive_evidence_and_benign_or_failed_variants():
    cases = [
        (event('GetConnection', {'name': 'lab'}, True), 'aws-glue-read-connection-credentials',
         lambda r: r.update(hidePassword=True)),
        (event('UpdateTable', {'databaseName': 'lab', 'tableInput': {'name': 'table',
         'storageDescriptor': {'location': 's3://canary/new/'}}, 'skipArchive': True}),
         'aws-glue-poison-table-location', lambda r: r.update(skipArchive=False)),
        (event('UpdateJob', {'jobName': 'lab', 'jobUpdate': {'command': {
         'scriptLocation': 's3://canary/changed.py'}}}),
         'aws-glue-update-job-script', lambda r: r['jobUpdate'].update(command={})),
        (event('CreateTrigger', {'name': 'lab', 'type': 'SCHEDULED',
         'schedule': 'cron(0 0 1 1 ? 2099)', 'startOnCreation': True,
         'actions': [{'jobName': 'lab'}]}),
         'aws-glue-recurring-job-trigger', lambda r: r.update(startOnCreation=False)),
    ]
    for item, technique, benign_change in cases:
        assert hits(item) == {technique}
        failed = {**item, 'errorCode': 'AccessDeniedException'}
        assert hits(failed) == set()
        wrong_category = {**item, 'managementEvent': False}
        assert hits(wrong_category) == set()
        benign = deepcopy(item)
        benign_change(benign['requestParameters'])
        assert hits(benign) == set()


def test_external_catalog_metadata_grant_and_same_account_negative():
    account = '222233334444'
    statement = {'Effect': 'Allow', 'Principal': '*', 'Action': 'glue:GetDatabase',
                 'Resource': f'arn:aws:glue:us-east-1:{account}:database/canary',
                 'Condition': {'StringEquals': {'aws:PrincipalAccount': '111111111111'}}}
    item = event('PutResourcePolicy', {'policyInJson': json.dumps({'Statement': [statement]})})
    assert hits(item) == {'aws-glue-external-catalog-resource-policy'}
    same = deepcopy(item)
    statement['Condition']['StringEquals']['aws:PrincipalAccount'] = account
    same['requestParameters']['policyInJson'] = json.dumps({'Statement': [statement]})
    assert hits(same) == set()
    deny = deepcopy(item)
    statement['Effect'] = 'Deny'
    deny['requestParameters']['policyInJson'] = json.dumps({'Statement': [statement]})
    assert hits(deny) == set()
