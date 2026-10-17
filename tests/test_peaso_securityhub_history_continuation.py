"""Adversarial local continuations for the registered Security Hub SLA path."""
from datetime import datetime, timedelta, timezone

import pytest
from botocore.stub import ANY

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from test_peaso_aws_wave_semantics_native_integration import (
    ACTOR, FILTERS, PRODUCT, SCOPE, finding, history_record,
)
from peaso.collectors import aws, aws_wave_semantics_native as native
from peaso.collectors.bulk_evidence import collect as collect_bulk
from peaso.engine import evaluate_snapshot


def _run(sdk, monkeypatch, created, records, *, finding_status='NOTIFIED',
         second_page=None, second_error=False):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    hub = add('securityhub')
    hub.add_response('get_findings', {'Findings': [finding(created, finding_status)]}, FILTERS)
    query = {'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': PRODUCT},
             'EndTime': ANY, 'MaxResults': 100}
    if records is not None:
        hub.add_response('get_finding_history', {'Records': records, 'NextToken': 'more'}, query)
        if second_error:
            hub.add_client_error('get_finding_history', 'AccessDeniedException',
                                 expected_params={**query, 'NextToken': 'more'})
        else:
            hub.add_response('get_finding_history', {'Records': second_page},
                             {**query, 'NextToken': 'more'})
    snapshot = collect_bulk(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {
        'service_concurrency': 1, 'retries': 0,
        'compliance_parameters': {'approved_response_hours': 4,
            'approved_response_identity_arns': [ACTOR]}}},
        ['securityhub_finding', native.KIND])
    history = next(c for c in snapshot['collections'] if c['type'] == native.KIND)['items'][0]
    verdict = evaluate_snapshot(snapshot, checks=['aws_incident_workflow_sla'])['findings'][0]
    hub.assert_no_pending_responses()
    sts.assert_no_pending_responses()
    return history, verdict


def test_late_page_error_cannot_certify_earlier_response(sdk, monkeypatch):
    created = datetime.now(timezone.utc) - timedelta(days=1)
    response = history_record(created, offset=2)
    history, verdict = _run(sdk, monkeypatch, created, [history_record(created), response],
                            second_error=True)
    assert history['complete'] is False
    assert history['Records'] == []
    assert verdict['status'] == 'UNKNOWN'


def test_duplicate_creation_across_pages_withholds_verdict(sdk, monkeypatch):
    created = datetime.now(timezone.utc) - timedelta(days=1)
    creation = history_record(created)
    history, verdict = _run(sdk, monkeypatch, created,
                            [creation, history_record(created, offset=2)],
                            second_page=[creation])
    assert history['complete'] is False
    assert verdict['status'] == 'UNKNOWN'


def test_duplicate_transition_across_pages_has_ambiguous_order(sdk, monkeypatch):
    created = datetime.now(timezone.utc) - timedelta(days=1)
    response = history_record(created, offset=2)
    history, verdict = _run(sdk, monkeypatch, created, [response],
                            second_page=[response, history_record(created)])
    assert history['complete'] is True
    assert verdict['status'] == 'UNKNOWN'
    assert 'order ambiguous' in str(verdict['evidence'])


def test_retention_boundary_withholds_unread_history(sdk, monkeypatch):
    created = datetime.now(timezone.utc) - timedelta(days=91)
    history, verdict = _run(sdk, monkeypatch, created, None)
    assert history['complete'] is False
    assert history['_coverage']['history']['reason'] == 'creation_older_than_history_retention'
    assert verdict['status'] == 'UNKNOWN'
