"""Native proposal composition with one documented ProtoJSON scalar default.

The proposal, association resolver and OCI Reader remain immutable. Capture
retains original response bodies and hashes; only the binding copy defaults
an omitted Job.reconciling to false. Explicit null/true/malformed values fail.
https://raw.githubusercontent.com/googleapis/googleapis/master/google/cloud/run/v2/job.proto
https://protobuf.dev/programming-guides/json/#presence-and-default-values
"""
from copy import deepcopy
import time

from . import gcp_cloudrun_v2_job_declared_images_20261020 as proposal
from . import gcp_image_secret_indicators as native


def bind(selection, scope, bodies):
    for body, (_, fields) in zip(bodies, proposal._requests(selection, scope)):
        proposal._shape(body, fields)
    normalized = deepcopy(bodies)
    if 'reconciling' not in normalized[0]:
        normalized[0]['reconciling'] = False
    return proposal._bind(selection, scope, normalized)


def collect_native(transport, *, scope, selectors):
    """Use the accepted native GET, binding and OCI inspection implementations.

    This explicit orchestration successor differs only at the binding call;
    no callable is synthesized, cloned, replaced or installed in the proposal.
    """
    selections = proposal.normalize_selection(selectors, scope)
    result = {'schema': proposal.SCHEMA, 'status': 'UNKNOWN', 'complete': False,
        'reason': 'invalid_selection_or_reader_unavailable', 'scope': scope,
        'association_kind': 'desired_digest_declaration', 'runtime_association_status': 'UNKNOWN',
        'observed_runtime_digest': None, 'deployed_bytes_proven': False,
        'rows': [], 'source_requests': [], 'metadata_captures': []}
    metadata_session = image_session = reader = capture = None
    try:
        metadata_session = proposal._session()
        image_session = proposal._session()
        end = time.monotonic() + proposal.MAX_SECONDS
        capture = proposal.Capture(transport, metadata_session, end, scope)
        reader = native.Reader(transport, session=image_session)
        reader.end = min(reader.end, end)
        for selection in selections:
            row = {'selection': selection, 'status': 'UNKNOWN', 'complete': False,
                'association_revalidated': False, 'content': {'complete': False, 'leaks': []},
                'reason': 'declaration_or_metadata_unavailable', 'source_requests': []}
            result['rows'].append(row)
            metadata_start, image_start = len(capture.records), len(reader.request_ids)
            try:
                requests = proposal._requests(selection, scope)
                before = [capture.get(*request) for request in requests]
                declaration, image = bind(selection, scope, before)
                row['declaration'] = declaration
                row['content'] = proposal._inspect(image, scope, before[2], before[1], reader)
                row['reason'] = 'metadata_changed_or_revalidation_unavailable'
                after = [capture.get(*request) for request in requests]
                bind(selection, scope, after)
                proposal._require(before == after, 'metadata_changed')
                row.update(association_revalidated=True, complete=row['content']['complete'],
                    status='FAIL' if row['content']['leaks'] else 'PASS' if row['content']['complete'] else 'UNKNOWN',
                    reason=row['content']['reason'])
            except Exception:
                pass
            finally:
                row['source_requests'] = ([r['id'] for r in capture.records[metadata_start:]]
                                          + reader.request_ids[image_start:])
        result['complete'] = all(row['complete'] for row in result['rows'])
        result['status'] = ('FAIL' if any(row['status'] == 'FAIL' for row in result['rows']) else
                            'PASS' if result['complete'] else 'UNKNOWN')
        result['reason'] = None if result['complete'] else 'selected_declaration_scope_incomplete'
    except Exception:
        pass
    finally:
        if capture is not None:
            result['source_requests'] = deepcopy(capture.records)
            result['metadata_captures'] = deepcopy(capture.captures)
        if reader is not None:
            result['source_requests'].extend(deepcopy(r) for r in getattr(transport, 'evidence', [])
                                             if r.get('id') in reader.request_ids)
        for session in (metadata_session, image_session):
            if session is not None:
                try:
                    session.close()
                except Exception:
                    result.update(complete=False, reason='session_cleanup_incomplete')
                    if result['status'] != 'FAIL':
                        result['status'] = 'UNKNOWN'
    return result
