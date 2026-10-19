"""Public admission and installed native collector-to-engine stored-log path."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from peaso import engine, collectors
from peaso.collectors import gcp
from peaso.checks import gcp_clouddeploy_source_secret_review_20261019 as check
from peaso.collectors import gcp_clouddeploy_source_secret_indicators as source
from peaso.server.validation import validate_connector
from tests.test_gcp_clouddeploy_source_secret_review_20261019 import (fixture, replies, NAME, SCOPE, TOKEN, archive)


def installed(monkeypatch, payload=b'completed\n', *, enabled=True, kinds=None, mock_engines=True):
    options = {'content_secret_scans': enabled,
               '_content_secret_scan_kinds': [source.KIND] if kinds is None else kinds}
    parent, calls, _, pending, _ = fixture(monkeypatch, replies(archive(payload)), options=options, mock_engines=mock_engines)
    native = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': parent.options},
        requirements=[source.KIND, 'project', 'bucket'], transport=parent.transport)
    snapshot = native.collect()
    return snapshot, calls, pending


def test_installed_native_collector_and_engine_accept_only_observed_generation(monkeypatch):
    snapshot, calls, pending = installed(monkeypatch)
    findings = engine.evaluate_snapshot(snapshot, checks=[check.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'PASS', findings
    evidence = findings[0]['evidence']
    assert evidence['coverage'] == 'observed_object_generation_only'
    assert evidence['historical_release_bytes'] == 'not_established'
    assert snapshot['metadata']['clouddeploy_release_source_authorized'] is True
    assert len([request for request in calls if request[2].get('stream')]) == 4
    assert not pending


def test_installed_real_dual_detector_leak_is_one_redacted_finding(monkeypatch):
    snapshot, _, _ = installed(monkeypatch, ('token="' + TOKEN + '"\n').encode(), mock_engines=False)
    findings = engine.evaluate_snapshot(snapshot, checks=[check.CHECK_ID])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL', findings
    assert len(findings[0]['evidence']['secret_leaks']) == 1
    assert {d['engine'] for d in findings[0]['evidence']['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in repr(snapshot) + repr(findings)


@pytest.mark.parametrize('enabled,kinds', [(False, [source.KIND]), (True, [])])
def test_unselected_installed_content_is_unknown_and_performs_no_payload_reads(monkeypatch, enabled, kinds):
    snapshot, calls, pending = installed(monkeypatch, enabled=enabled, kinds=kinds)
    assert not any(kw.get('stream') for _, _, kw in calls)
    assert pending
    collection = next(c for c in snapshot['collections'] if c['type'] == source.KIND)
    assert collection['status'] == 'unknown' and collection['coverage_status'] == 'unavailable'
    assert all(f['status'] == 'UNKNOWN' for f in engine.evaluate_snapshot(snapshot,
        checks=[check.CHECK_ID])['findings'])


def test_public_named_check_derives_exact_authorization_and_dependencies(monkeypatch):
    from peaso.snapshot import make_snapshot
    seen = []
    def collect(connector, requirements):
        seen.append((deepcopy(connector), set(requirements)))
        return make_snapshot('gcp', [SCOPE], [])
    monkeypatch.setattr(collectors, 'collect_live', collect)
    request = {'connector': {'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'content_secret_scans': True, 'selected_clouddeploy_releases': [NAME]}}, 'checks': [check.CHECK_ID]}
    engine.collect_snapshot(request)
    connector, dependencies = seen.pop()
    assert connector['options']['_content_secret_scan_kinds'] == [source.KIND]
    assert {source.KIND, 'project', 'bucket'} <= dependencies
    for selection in ({}, {'categories': ['hardening']}, {'frameworks': ['HackTricks Cloud Best Practices']}):
        engine.collect_snapshot({'connector': request['connector'], **selection})
        connector, _ = seen.pop()
        assert source.KIND not in connector['options']['_content_secret_scan_kinds']


def test_public_and_sdk_selection_validation_precedes_authentication(monkeypatch):
    settings = SimpleNamespace(auth_mode='local')
    validate_connector('gcp', {}, {'selected_clouddeploy_releases': [NAME]}, settings, scopes=[SCOPE])
    for rows in (None, [], [NAME, NAME], [NAME.replace('/review/', '/foreign/')]):
        with pytest.raises(HTTPException):
            validate_connector('gcp', {}, {'selected_clouddeploy_releases': rows}, settings, scopes=[SCOPE])
        with pytest.raises(ValueError):
            gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': {
                'selected_clouddeploy_releases': rows}}, requirements=[source.KIND])
