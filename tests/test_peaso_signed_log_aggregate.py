"""Directed registered signed-log aggregation regression tests (local evidence only)."""
from __future__ import annotations

import base64
import copy

import pytest

from peaso.checks import evaluate_check
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw23",)):
    from test_peaso_compliance_new_sw23 import (
        ACCOUNT, CONTAINER, fixture, index, signed_container, signing_key, sw,
    )


def second_container(key, cid):
    item = signed_container(key, completeness=cid == sw.COMPLETENESS)
    other = CONTAINER.replace('/containers/logs', '/containers/other')
    item['id'] = other
    item['manifest']['payload']['container_id'] = other
    # A different container changes signed bytes: re-sign this fixture so only
    # blob availability is unresolved, without an independent signature failure.
    import json
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    canonical = json.dumps(item['manifest']['payload'], sort_keys=True,
                           separators=(',', ':'), ensure_ascii=False).encode()
    item['manifest']['signature_base64'] = base64.b64encode(
        key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())).decode()
    item['blobs']['items'][0]['read_complete'] = False
    return item


@pytest.mark.parametrize('cid', [sw.INTEGRITY, sw.COMPLETENESS])
@pytest.mark.parametrize('unresolved_first', [False, True])
def test_verified_failure_survives_other_unresolved_container(signing_key, cid, unresolved_first):
    row, ev = fixture(cid, signing_key)
    bad = ev['containers']['items'][0]
    if cid == sw.INTEGRITY:
        bad['blobs']['items'][0]['content_base64'] = base64.b64encode(b'changed').decode()
    else:
        bad['baseline']['expected_sequences'] = [1, 2]
    unresolved = second_container(signing_key, cid)
    if unresolved_first:
        unresolved['blobs']['items'][0]['read_complete'] = True
        unresolved['trusted_key']['jwk']['n'] = 'AA'  # malformed RSA modulus
    ev['containers']['items'] = [unresolved, bad] if unresolved_first else [bad, unresolved]
    status, evidence = evaluate_check(cid, row, index(cid, row, ev))
    assert status == 'FAIL'
    assert evidence['unresolved_container_ids'] == [unresolved['id']]
    gaps = evidence['manifest_integrity_gaps' if cid == sw.INTEGRITY else 'verified_log_deletion_or_digest_gaps']
    assert [gap['container_id'] for gap in gaps] == [bad['id']]


def test_unresolved_only_never_passes(signing_key):
    for cid in (sw.INTEGRITY, sw.COMPLETENESS):
        row, ev = fixture(cid, signing_key)
        ev['containers']['items'][0]['blobs']['items'][0]['read_complete'] = False
        status, evidence = evaluate_check(cid, row, index(cid, row, ev))
        assert status == 'UNKNOWN'
        assert evidence['unresolved_container_ids'] == [CONTAINER]


def test_global_guards_remain_unknown(signing_key):
    for cid in (sw.INTEGRITY, sw.COMPLETENESS):
        for case in ('duplicate', 'scope', 'inventory', 'identity', 'provenance'):
            row, ev = fixture(cid, signing_key)
            bad = ev['containers']['items'][0]
            bad['blobs']['items'][0]['content_base64'] = base64.b64encode(b'changed').decode()
            if case == 'duplicate':
                ev['containers']['items'].append(copy.deepcopy(bad))
            elif case == 'scope':
                ev['protected_scope_authoritative'] = False
            elif case == 'inventory':
                ev['containers']['collection_status'] = 'partial'
            elif case == 'identity':
                bad['id'] = ACCOUNT + '/blobServices/default/containers/other/foreign'
            facts = index(cid, row, ev)
            if case == 'provenance':
                facts['collections']['signed_log_evidence'][0]['items'][0]['_provenance']['complete'] = False
            status, _ = evaluate_check(cid, row, facts)
            assert status == 'UNKNOWN', (cid, case)
