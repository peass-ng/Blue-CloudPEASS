"""Registered enumeration logging requires independent persisted sink observations."""
import copy
import json
from pathlib import Path

import pytest
from peaso.checks import CHECKS

CID = 'azure.other.enumeration_logging'
CASE = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())[CID]
CHECK = next(c for c in CHECKS if c.id == CID)
SCOPE = CASE['pass']['scope']
SINK = SCOPE + '/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs'


def evaluate(case, branch='pass'):
    return CHECK.evaluate(copy.deepcopy(case[branch]), copy.deepcopy(case[branch + '_index']))[0]


def bare_case():
    case = copy.deepcopy(CASE)
    index = case['pass_index']
    metadata = index['context']['metadata']
    metadata.pop('credential_context_id', None)
    metadata.pop('customer_context_id', None)
    policy = metadata['compliance_policy']['sw26'][CID]
    for field in ('eventSourceId', 'logSourceId', 'approvedSinkIds', 'observedSinkId'):
        policy.pop(field, None)
    for kind in ('enumeration_event', 'enumeration_log_record'):
        env = index['collections'][kind][0]
        env.pop('_provenance', None)
        for row in env['items']:
            row.pop('persistedAt', None)
            row.pop('sinkId', None)
        index[kind] = [{'type': kind, 'scope': SCOPE, 'data': copy.deepcopy(row)} for row in env['items']]
    return case


def external_case():
    case = bare_case()
    index = case['pass_index']
    meta = index['context']['metadata']
    meta.update(credential_context_id='capture-1', customer_context_id='customer-1')
    policy = meta['compliance_policy']['sw26'][CID]
    policy.update(eventSourceId='event-observer', logSourceId='sink-reader',
                  approvedSinkIds=[SINK], observedSinkId=SINK)
    common = {'scope': SCOPE, 'readOnly': True, 'observer': 'external-observer',
              'authorizationDocumentId': 'independent-evidence-doc',
              'credential_context_id': 'capture-1', 'customer_context_id': 'customer-1',
              'observedAt': '2026-10-11T12:00:00Z'}
    event_env = index['collections']['enumeration_event'][0]
    event_env['_provenance'] = {**common, 'sourceOperation': 'external_independent_event_inventory',
        'sourceId': 'event-observer', 'coverage': {'status': 'complete',
        'windowStart': policy['window_start'], 'windowEnd': policy['window_end']}}
    log_env = index['collections']['enumeration_log_record'][0]
    log_env['_provenance'] = {**common, 'sourceOperation': 'external_persisted_sink_read',
        'sourceId': 'sink-reader', 'sinkId': SINK, 'coverage': {'status': 'complete',
        'windowStart': policy['window_start'], 'windowEnd': '2026-10-11T00:00:00Z'}}
    for row in log_env['items']:
        row.update(sinkId=SINK, persistedAt='2026-10-05T00:01:00Z')
    for kind in ('enumeration_event', 'enumeration_log_record'):
        env = index['collections'][kind][0]
        index[kind] = [{'type': kind, 'scope': SCOPE, 'data': copy.deepcopy(row)} for row in env['items']]
    return case


def test_bare_matching_rows_cannot_prove_persisted_logging():
    assert evaluate(bare_case()) == 'UNKNOWN'


def test_independent_current_persisted_sink_read_passes():
    assert evaluate(external_case()) == 'PASS'


@pytest.mark.parametrize('mutation,expected', [
    ('complete_missing_record', 'FAIL'), ('late_persistence', 'FAIL'),
    ('same_source', 'UNKNOWN'), ('foreign_customer', 'UNKNOWN'),
    ('incomplete_event_window', 'UNKNOWN'), ('incomplete_log_window', 'UNKNOWN'),
    ('unapproved_sink', 'UNKNOWN'), ('record_foreign_sink', 'UNKNOWN'),
    ('missing_persisted_at', 'UNKNOWN'), ('empty_events', 'UNKNOWN'),
])
def test_source_window_sink_and_persistence_boundaries(mutation, expected):
    case = external_case()
    index = case['pass_index']
    policy = index['context']['metadata']['compliance_policy']['sw26'][CID]
    event_env = index['collections']['enumeration_event'][0]
    log_env = index['collections']['enumeration_log_record'][0]
    if mutation == 'complete_missing_record':
        log_env['items'] = []; log_env['status'] = 'empty'; index['enumeration_log_record'] = []
    elif mutation == 'late_persistence':
        log_env['items'][0]['persistedAt'] = '2026-10-06T00:00:01Z'
    elif mutation == 'same_source':
        policy['logSourceId'] = policy['eventSourceId']
        log_env['_provenance']['sourceId'] = policy['eventSourceId']
    elif mutation == 'foreign_customer':
        log_env['_provenance']['customer_context_id'] = 'other-customer'
    elif mutation == 'incomplete_event_window':
        event_env['_provenance']['coverage']['status'] = 'partial'
    elif mutation == 'incomplete_log_window':
        log_env['_provenance']['coverage']['windowEnd'] = '2026-10-10T00:00:00Z'
    elif mutation == 'unapproved_sink':
        policy['approvedSinkIds'] = [SCOPE + '/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/other']
    elif mutation == 'record_foreign_sink':
        log_env['items'][0]['sinkId'] = SCOPE + '/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/foreign'
    elif mutation == 'missing_persisted_at':
        log_env['items'][0].pop('persistedAt')
    elif mutation == 'empty_events':
        event_env['items'] = []; event_env['status'] = 'empty'; index['enumeration_event'] = []
    if mutation not in ('complete_missing_record', 'empty_events'):
        for kind in ('enumeration_event', 'enumeration_log_record'):
            env = index['collections'][kind][0]
            index[kind] = [{'type': kind, 'scope': SCOPE, 'data': copy.deepcopy(row)} for row in env['items']]
    assert evaluate(case) == expected
