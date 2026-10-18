"""SDK-backed finding metadata projection, with no sensitive sample retention."""
import json

import pytest

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_macie_findings_native as native
from peaso.collectors.bulk_evidence import collect as collect_bulk
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = 'eu-west-1'
BUCKET = 'arn:aws:s3:::owned-macie-fixture'
IDENTIFIER = f'arn:aws:macie2:{REGION}:{ACCOUNT}:custom-data-identifier/identifier123'
MARKER = 'SENSITIVE-CONTENT-MUST-NOT-BE-CACHED'
CHECK = 'aws.pci.s3.sensitive_auth_data_findings'
LIST_ARGS = {'maxResults': 50, 'findingCriteria': {'criterion': {'accountId': {'eq': [ACCOUNT]}, 'region': {'eq': [REGION]}}}}


def finding(identifier='finding1', archived=False):
    return {'id': identifier, 'accountId': ACCOUNT, 'region': REGION, 'partition': 'aws',
            'archived': archived, 'sample': False, 'category': 'CLASSIFICATION',
            'description': MARKER, 'title': MARKER,
            'resourcesAffected': {'s3Bucket': {'arn': BUCKET, 'name': 'owned-macie-fixture'},
                                  's3Object': {'bucketArn': BUCKET, 'key': MARKER, 'path': MARKER,
                                               'versionId': 'fixture-version-1', 'eTag': 'fixture-etag-1'}},
            'classificationDetails': {'detailedResultsLocation': MARKER,
                'originType': 'SENSITIVE_DATA_DISCOVERY_JOB', 'jobId': 'a' * 32,
                'jobArn': f'arn:aws:macie2:{REGION}:{ACCOUNT}:classification-job/' + 'a' * 32,
                'result': {
                'status': {'code': 'COMPLETE'}, 'customDataIdentifiers': {'totalCount': 1,
                    'detections': [{'arn': IDENTIFIER, 'name': 'prohibited-auth', 'count': 1,
                                    'occurrences': {'cells': [{'columnName': MARKER, 'row': 1}]}}]}}}}


def test_real_sdk_page_and_precache_projection_preserve_only_metadata(sdk):
    session, add = sdk; stub = add('macie2')
    stub.add_response('list_findings', {'findingIds': [], 'nextToken': 'second'}, LIST_ARGS)
    stub.add_response('list_findings', {'findingIds': ['finding1']}, {**LIST_ARGS, 'nextToken': 'second'})
    stub.add_response('get_findings', {'findings': [finding()]}, {'findingIds': ['finding1']})
    requests = aws.Requests({'retries': 0})
    result = native.collect(requests, session, REGION, ACCOUNT)
    assert result.status == 'collected' and requests.calls == 3
    row, = result.items
    assert row['s3Object']['bucketArn'] == BUCKET and row['customIdentifierNames'] == ['prohibited-auth']
    assert 'key' not in row['s3Object'] and len(row['s3Object']['objectIdentitySha256']) == 64
    assert row['s3Object']['versionId'] == 'fixture-version-1'
    assert row['classificationOrigin']['jobArn'].endswith('/' + 'a' * 32)
    assert row['archived'] is False and row['_provenance']['scan_coverage_established'] is False
    cached = [value.result() if hasattr(value, 'result') else value for value in requests._cache.values()]
    assert MARKER not in json.dumps(cached) and MARKER not in json.dumps(result.items)
    safe = next(value for value in cached if value.get('_metadata_projection') == native.PROJECTION)
    assert safe['findings'][0]['_provenance']['custom_identifier_bindings'] == [{'name': 'prohibited-auth', 'arn': IDENTIFIER, 'count': 1}]
    assert 'classificationDetails' not in safe['findings'][0]
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['list_denied', 'get_denied', 'page_budget', 'missing_detail', 'wrong_detail_id',
                                  'foreign_account', 'foreign_region', 'foreign_partition'])
def test_incomplete_or_foreign_native_inventory_never_passes(sdk, mode):
    session, add = sdk; stub = add('macie2')
    if mode == 'list_denied':
        stub.add_client_error('list_findings', 'AccessDeniedException', expected_params=LIST_ARGS)
    else:
        stub.add_response('list_findings', {'findingIds': ['finding1'], **({'nextToken': 'next'} if mode == 'page_budget' else {})}, LIST_ARGS)
        if mode == 'get_denied':
            stub.add_client_error('get_findings', 'AccessDeniedException', expected_params={'findingIds': ['finding1']})
        elif mode != 'page_budget':
            row = finding()
            if mode == 'wrong_detail_id': row['id'] = 'foreign'
            if mode == 'foreign_account':
                row['accountId'] = '999999999999'
                row['classificationDetails']['result']['customDataIdentifiers']['detections'][0]['arn'] = IDENTIFIER.replace(ACCOUNT, row['accountId'])
            if mode == 'foreign_region':
                row['region'] = 'us-east-1'
                row['classificationDetails']['result']['customDataIdentifiers']['detections'][0]['arn'] = IDENTIFIER.replace(REGION, row['region'])
            if mode == 'foreign_partition': row['partition'] = 'aws-cn'
            stub.add_response('get_findings', {'findings': [] if mode == 'missing_detail' else [row]}, {'findingIds': ['finding1']})
    requests = aws.Requests({'retries': 0, **({'max_pages': 1} if mode == 'page_budget' else {})})
    result = native.collect(requests, session, REGION, ACCOUNT)
    assert result.status not in {'collected', 'empty'}
    assert MARKER not in str(result.items)
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['bucket_name_conflict', 'object_bucket_conflict', 'foreign_identifier',
                                  'duplicate_identifier', 'missing_archive', 'missing_sample'])
def test_malformed_bound_metadata_is_rejected_before_any_raw_cache(mode):
    row = finding()
    if mode == 'bucket_name_conflict': row['resourcesAffected']['s3Bucket']['name'] = 'foreign-bucket'
    elif mode == 'object_bucket_conflict': row['resourcesAffected']['s3Object']['bucketArn'] = 'arn:aws:s3:::foreign-bucket'
    elif mode == 'foreign_identifier': row['classificationDetails']['result']['customDataIdentifiers']['detections'][0]['arn'] = IDENTIFIER.replace(ACCOUNT, '999999999999')
    elif mode == 'duplicate_identifier': row['classificationDetails']['result']['customDataIdentifiers']['detections'] *= 2
    elif mode == 'missing_archive': row.pop('archived')
    elif mode == 'missing_sample': row.pop('sample')
    with pytest.raises(aws.ReadFailure): native.project_response({'findings': [row]})


@pytest.mark.parametrize('mode', ['partial_analysis', 'missing_custom_block', 'custom_total_conflict'])
def test_unproved_classification_metadata_retains_unknown(sdk, mode):
    session, add = sdk; stub = add('macie2'); row = finding()
    result = row['classificationDetails']['result']
    if mode == 'partial_analysis': result['status']['code'] = 'PARTIAL'
    elif mode == 'missing_custom_block': result.pop('customDataIdentifiers')
    elif mode == 'custom_total_conflict': result['customDataIdentifiers']['totalCount'] = 2
    stub.add_response('list_findings', {'findingIds': ['finding1']}, LIST_ARGS)
    stub.add_response('get_findings', {'findings': [row]}, {'findingIds': ['finding1']})
    read = native.collect(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    assert read.status == 'partial' and read.error['code'] == 'macie_classification_metadata_incomplete'
    stub.assert_no_pending_responses()


def test_sample_findings_are_not_real_detection_evidence(sdk):
    session, add = sdk; stub = add('macie2')
    stub.add_response('list_findings', {'findingIds': ['sample1']}, LIST_ARGS)
    stub.add_response('get_findings', {'findings': [{'id': 'sample1', 'sample': True, 'description': MARKER}]}, {'findingIds': ['sample1']})
    read = native.collect(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    assert read.status == 'empty' and read.items == []
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('mode', ['duplicate_ids', 'inventory_cap'])
def test_invalid_or_over_budget_finding_ids_never_trigger_detail_reads(sdk, mode):
    session, add = sdk; stub = add('macie2')
    ids = ['finding1', 'finding1'] if mode == 'duplicate_ids' else ['finding'+str(i) for i in range(native.MAX_FINDINGS+1)]
    stub.add_response('list_findings', {'findingIds': ids}, LIST_ARGS)
    requests = aws.Requests({'retries': 0})
    read = native.collect(requests, session, REGION, ACCOUNT)
    assert read.status == 'malformed' and read.items == [] and requests.calls == 1
    stub.assert_no_pending_responses()


def test_sdk_detail_batch_size_is_at_most_fifty(sdk):
    session, add = sdk; stub = add('macie2'); ids = ['finding'+str(i) for i in range(51)]
    stub.add_response('list_findings', {'findingIds': ids}, LIST_ARGS)
    for chunk in (ids[:50], ids[50:]):
        stub.add_response('get_findings', {'findings': [finding(i) for i in chunk]}, {'findingIds': chunk})
    read = native.collect(aws.Requests({'retries': 0}), session, REGION, ACCOUNT)
    assert read.status == 'collected' and len(read.items) == 51
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('full', [False, True])
def test_full_collection_accepts_more_than_private_finding_cap_and_default_stays_bounded(full):
    identifiers = ['finding'+str(i) for i in range(native.MAX_FINDINGS+1)]
    class Reads:
        collect_all = full
        batches = []
        def pages(self, *args, **kwargs):
            assert kwargs['_page_limit'] == (None if full else 32)
            return aws.ReadResult(identifiers, 'collected')
        def detail(self, *args, findingIds):
            assert full and 1 <= len(findingIds) <= 50
            self.batches.append(list(findingIds))
            projected = native.project_response({'findings': [finding(identifier) for identifier in findingIds]})
            return {**projected, 'collection_status': 'collected'}
    requests = Reads()
    result = native.collect(requests, None, REGION, ACCOUNT)
    if full:
        assert result.status == 'collected' and len(result.items) == len(identifiers)
        assert [identifier for batch in requests.batches for identifier in batch] == identifiers
    else:
        assert result.status == 'malformed' and result.items == [] and requests.batches == []


def test_full_collection_still_obeys_explicit_global_page_budget(sdk):
    session, add = sdk; stub = add('macie2')
    stub.add_response('list_findings', {'findingIds': ['finding1'], 'nextToken': 'more'}, LIST_ARGS)
    requests = aws.Requests({'collect_all': True, 'max_pages': 1, 'retries': 0})
    assert requests.collect_all is True
    result = native.collect(requests, session, REGION, ACCOUNT)
    assert result.status not in {'collected', 'empty'} and result.items == [] and requests.calls == 1
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('archived,expected', [(False, 'FAIL'), (True, 'PASS')])
def test_actual_finding_projection_matches_signed_fields_only_with_separate_explicit_coverage(archived, expected):
    # This isolated evaluator fixture is explicit test-only coverage, not produced
    # by ListFindings or inferred from session/jobs/empty result configuration.
    row = native.project_response({'findings': [finding(archived=archived)]})['findings'][0]
    row.pop('_classification_metadata_complete')
    scope = ACCOUNT + '/' + REGION
    snapshot = make_snapshot('aws', [scope], [
        {'type': 'macie_finding', 'scope': scope, 'status': 'collected', 'items': [row]},
        {'type': 'macie_scan_coverage', 'scope': scope, 'status': 'collected',
         'items': [{'authorized': True, 'complete': True, 'bucketArns': [BUCKET]}]}],
        metadata={'parameters': {'prohibited_auth_identifier_names': ['prohibited-auth'], 'authorized_macie_bucket_arns': [BUCKET]}})
    assert {item['status'] for item in evaluate_snapshot(snapshot, checks=[CHECK])['findings']} == {expected}


def test_public_collector_collects_finding_but_does_not_invent_scan_coverage(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-pinned'))
    sts = add('sts'); sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    macie = add('macie2')
    macie.add_response('list_findings', {'findingIds': ['finding1']}, LIST_ARGS)
    macie.add_response('get_findings', {'findings': [finding()]}, {'findingIds': ['finding1']})
    snapshot = collect_bulk(aws, {'provider': 'aws', 'scopes': [ACCOUNT + '/' + REGION], 'options': {
        'service_concurrency': 1, 'compliance_parameters': {
            'prohibited_auth_identifier_names': ['prohibited-auth'], 'authorized_macie_bucket_arns': [BUCKET]}}},
        ['macie_finding', 'macie_scan_coverage'])
    collection = next(row for row in snapshot['collections'] if row['type'] == 'macie_finding')
    coverage = next(row for row in snapshot['collections'] if row['type'] == 'macie_scan_coverage')
    assert collection['status'] == 'collected' and collection['items'][0]['customIdentifierNames'] == ['prohibited-auth']
    assert coverage['status'] == 'not_collected' and coverage['items'] == []
    assert MARKER not in str(snapshot)
    # A scoped known active violation is conclusive even though no scan-wide
    # absence claim is available. Missing coverage can never establish PASS.
    assert {row['status'] for row in evaluate_snapshot(snapshot, checks=[CHECK])['findings']} == {'FAIL'}
    macie.assert_no_pending_responses(); sts.assert_no_pending_responses()
