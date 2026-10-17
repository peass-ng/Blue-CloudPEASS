"""A verified detector hit is independent of another incomplete classification."""
from copy import deepcopy
import json

import pytest

from test_peaso_aws_bulk_inventory import sdk
from tests.test_peaso_aws_macie_findings_native import finding, ACCOUNT, REGION, BUCKET, MARKER, CHECK, LIST_ARGS
from peaso.collectors import aws, aws_macie_findings_native as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def capture(sdk, reverse=False, mode='other_partial'):
    session, add = sdk
    stub = add('macie2')
    known, other = finding('confirmed'), finding('incomplete')
    other['classificationDetails']['result'].pop('customDataIdentifiers')
    if mode == 'other_partial': other['classificationDetails']['result']['status']['code'] = 'PARTIAL'
    if mode == 'other_missing_details': other.pop('classificationDetails')
    if mode == 'known_partial': known['classificationDetails']['result']['status']['code'] = 'PARTIAL'
    if mode == 'no_hit': known['classificationDetails']['result']['customDataIdentifiers']['detections'][0]['name'] = 'unrelated'
    if mode == 'mismatched_total': known['classificationDetails']['result']['customDataIdentifiers']['totalCount'] = 2
    if mode == 'sample': known['sample'] = True
    rows = [known, other]
    if reverse: rows.reverse()
    ids = [row['id'] for row in rows]
    stub.add_response('list_findings', {'findingIds': ids}, LIST_ARGS)
    stub.add_response('get_findings', {'findings': rows}, {'findingIds': ids})
    requests = aws.Requests({'retries': 0})
    read = native.collect(requests, session, REGION, ACCOUNT)
    stub.assert_no_pending_responses()
    cached = [f.result() if hasattr(f, 'result') else f for f in requests._cache.values()]
    assert MARKER not in json.dumps(cached)
    assert MARKER not in json.dumps(read.items)
    scope = ACCOUNT + '/' + REGION
    snapshot = make_snapshot('aws', [scope], [{'type': 'macie_finding', 'scope': scope, 'service': 'macie2',
        'status': read.status, 'items': read.items, **({'error': read.error} if read.error else {})}],
        metadata={'parameters': {'prohibited_auth_identifier_names': ['prohibited-auth'], 'authorized_macie_bucket_arns': [BUCKET]}})
    return snapshot, read, cached


def verdict(snapshot):
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CHECK])['findings'] if f['check_id'] == CHECK]
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('mode', ['other_partial', 'other_missing_details', 'known_partial'])
def test_confirmed_sdk_hit_survives_other_incomplete_classification(sdk, reverse, mode):
    snapshot, read, _ = capture(sdk, reverse, mode)
    assert read.status == 'partial' and len(read.items) == 2
    finding = verdict(snapshot)
    assert finding['status'] == 'FAIL'


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('mode', ['no_hit', 'mismatched_total', 'sample'])
def test_unverified_absent_or_sample_detector_is_never_a_partial_violation(sdk, reverse, mode):
    snapshot, read, _ = capture(sdk, reverse, mode)
    assert read.status == 'partial'
    assert verdict(snapshot)['status'] == 'UNKNOWN'


@pytest.mark.parametrize('field', ['scope', 'projection', 'readonly', 'total', 'count', 'arn', 'name', 'bucket', 'sample'])
def test_partial_counterexample_proof_cannot_be_relabelled_or_miscounted(sdk, field):
    snapshot, _, _ = capture(sdk)
    rows = snapshot['collections'][0]['items']
    row = next(r for r in rows if r['id'] == 'confirmed')
    proof = row['_provenance']
    if field == 'scope': proof['audited_scope'] = '999999999999/' + REGION
    elif field == 'projection': proof['metadata_projection'] = 'external-input'
    elif field == 'readonly': proof['read_only'] = 1
    elif field == 'total': proof['custom_identifier_total_count'] = 2
    elif field == 'count': proof['custom_identifier_bindings'][0]['count'] = True
    elif field == 'arn': proof['custom_identifier_bindings'][0]['arn'] = proof['custom_identifier_bindings'][0]['arn'].replace(ACCOUNT, '999999999999')
    elif field == 'name': proof['custom_identifier_bindings'][0]['name'] = 'different-name'
    elif field == 'bucket': row['s3Object']['bucketArn'] = 'arn:aws:s3:::unapproved-bucket'
    elif field == 'sample': row['sample'] = True
    sealed = make_snapshot('aws', snapshot['scopes'], snapshot['collections'], metadata=snapshot['metadata'], created_at=snapshot['created_at'])
    assert verdict(sealed)['status'] == 'UNKNOWN'
