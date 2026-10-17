"""Exact CID canonical admission and pre-contract negative shape."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from peaso.checks import evaluate_check

CID = 'azure_c5_ops_05_04ac'
FIXTURE = Path(__file__).parent / 'fixtures' / 'bulk_pending_behavior.json'


def _pass_index():
    return copy.deepcopy(json.loads(FIXTURE.read_text())[CID]['pass_index'])


def _export_rows(index):
    return (index['collections']['operational_deviation_evidence'][0]['items'][0],
            index['operational_deviation_evidence'][0]['data'])


def test_old_bare_external_export_stays_unknown():
    index = _pass_index()
    index['context']['metadata']['compliance_policy']['sw16'][CID].pop('specificationSourceId')
    for export in _export_rows(index):
        export.pop('capturedAt')
        export.pop('specificationSourceId')
        export['_provenance'].pop('observed_at')
        event = export['events'][0]
        for field in ('scope_id', 'exportId', 'specificationSourceId'):
            event.pop(field)
        event['_provenance'].pop('observed_at')
    assert evaluate_check(CID, {}, index)[0] == 'UNKNOWN'


def test_migrated_export_rejects_foreign_event_source():
    index = _pass_index()
    for export in _export_rows(index):
        export['events'][0]['_provenance']['source_operation'] = 'other-external-export'
    assert evaluate_check(CID, {}, index)[0] == 'UNKNOWN'
