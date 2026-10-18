"""Bounded import of externally reviewed clock measurements, never a native probe.

Review authorizes evidence provenance; it does not prove physical measurements.
No token, command, clock query, proxy request or verification flag is generated.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import math
import re

OPTION = 'node_clock_evidence'
SOURCE = 'external_reviewed_node_clock_measurement'
MAX_BYTES = 2_000_000
MAX_ROWS = 4096
REVIEW = {'cluster_id', 'kube_system_uid', 'reviewer_id', 'review_record_id',
          'reviewed_at', 'max_age_seconds', 'approved_observer_ids',
          'approved_reference_ids', 'reviewed_measurement_ids'}
ROW = {'node_name', 'node_uid', 'measurement_id', 'observer_id', 'reference_id',
       'measured_at', 'node_utc', 'reference_utc', 'uncertainty_seconds',
       'node_measurement_method', 'node_identity_record_id',
       'reference_protocol', 'reference_verification_record_id'}


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}', value):
        raise ValueError('clock evidence identity invalid')
    return value


def _date(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('clock timestamp invalid')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.utcoffset() is None:
            raise ValueError('clock timezone absent')
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError('clock timestamp invalid') from exc


def _array(value):
    if not isinstance(value, list) or not value or len(value) > MAX_ROWS:
        raise ValueError('clock evidence set invalid')
    if any(_id(v) != v for v in value) or len(value) != len(set(value)):
        raise ValueError('clock evidence set duplicate')


def validate_review(review):
    if not isinstance(review, dict) or set(review) != REVIEW:
        raise ValueError('clock evidence review fields invalid')
    for name in ('cluster_id', 'kube_system_uid', 'reviewer_id', 'review_record_id'):
        _id(review[name])
    _date(review['reviewed_at'])
    if type(review['max_age_seconds']) is not int or not 1 <= review['max_age_seconds'] <= 600:
        raise ValueError('clock evidence age invalid')
    for name in ('approved_observer_ids', 'approved_reference_ids', 'reviewed_measurement_ids'):
        _array(review[name])


def validate_row(row):
    if not isinstance(row, dict) or set(row) != ROW:
        raise ValueError('clock measurement fields invalid')
    for name in ROW - {'measured_at', 'node_utc', 'reference_utc', 'uncertainty_seconds'}:
        _id(row[name])
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', row['node_name']):
        raise ValueError('clock node name invalid')
    for name in ('measured_at', 'node_utc', 'reference_utc'):
        _date(row[name])
    uncertainty = row['uncertainty_seconds']
    if type(uncertainty) not in (int, float) or not 0 <= uncertainty <= 60 or not math.isfinite(uncertainty):
        raise ValueError('clock measurement uncertainty invalid')
    if row['node_measurement_method'] not in ('host_agent_clock_read', 'validated_kubelet_tls_date'):
        raise ValueError('clock node measurement method unsupported')
    # These identify the external records reviewed by the operator. They are
    # never turned into native verified=true flags or independently validated.
    if row['reference_protocol'] not in ('NTS', 'PTP-authenticated', 'GNSS-disciplined'):
        raise ValueError('clock reference verification method unsupported')


def normalize(options):
    if OPTION not in options:
        return None
    raw = options[OPTION]
    try:
        size = len(json.dumps(raw, allow_nan=False).encode())
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError('clock evidence must be JSON-safe') from exc
    if size > MAX_BYTES or not isinstance(raw, dict) or set(raw) != {'review', 'observations'}:
        raise ValueError('clock evidence envelope invalid')
    validate_review(raw['review'])
    rows = raw['observations']
    if not isinstance(rows, list) or not rows or len(rows) > MAX_ROWS:
        raise ValueError('clock observation count invalid')
    for row in rows:
        validate_row(row)
    return deepcopy(raw)


def validate_measurements(review, rows, nodes, namespaces, cluster_id, captured_at):
    """Revalidate imported facts against current, complete native identities."""
    validate_review(review)
    now = _date(captured_at)
    age = review['max_age_seconds']
    if review['cluster_id'] != cluster_id or not 0 <= (now - _date(review['reviewed_at'])).total_seconds() <= age:
        raise ValueError('clock review foreign or stale')
    system = [n for n in namespaces if n.get('metadata', {}).get('name') == 'kube-system']
    if len(system) != 1 or system[0].get('metadata', {}).get('uid') != review['kube_system_uid']:
        raise ValueError('clock cluster UID binding unavailable')
    current = {}
    native_uids = set()
    for node in nodes:
        metadata = node.get('metadata', {})
        name, uid = metadata.get('name'), metadata.get('uid')
        _id(name); _id(uid)
        if name in current or uid in native_uids:
            raise ValueError('clock native node duplicate')
        current[name] = uid
        native_uids.add(uid)
    if not current or len(current) > MAX_ROWS or len(rows) != len(current):
        raise ValueError('clock node coverage incomplete')
    names, measurements = set(), set()
    for row in rows:
        validate_row(row)
        name = row['node_name']
        if name in names or row['measurement_id'] in measurements or current.get(name) != row['node_uid']:
            raise ValueError('clock measurement duplicate or node UID mismatch')
        names.add(name); measurements.add(row['measurement_id'])
        if (row['observer_id'] not in review['approved_observer_ids'] or
                row['reference_id'] not in review['approved_reference_ids']):
            raise ValueError('clock measurement source not reviewed')
        measured = _date(row['measured_at'])
        reference = _date(row['reference_utc'])
        uncertainty = row['uncertainty_seconds']
        if not 0 <= (now - measured).total_seconds() <= age or abs((measured - reference).total_seconds()) > uncertainty:
            raise ValueError('clock measurement capture stale or reference time inconsistent')
    if names != set(current) or measurements != set(review['reviewed_measurement_ids']):
        raise ValueError('clock reviewed measurement set mismatch')


def verdict(review, rows, nodes, namespaces, cluster_id, captured_at, tolerance):
    validate_measurements(review, rows, nodes, namespaces, cluster_id, captured_at)
    if type(tolerance) is not int or not 0 <= tolerance <= 86400:
        raise ValueError('clock skew policy invalid')
    bad, uncertain = [], []
    for row in rows:
        delta = abs((_date(row['node_utc']) - _date(row['reference_utc'])).total_seconds())
        low, high = max(0, delta - row['uncertainty_seconds']), delta + row['uncertainty_seconds']
        if low > tolerance:
            bad.append(row['node_name'])
        elif high > tolerance:
            uncertain.append(row['node_name'])
    if uncertain:
        raise ValueError('clock uncertainty straddles approved skew')
    return bool(bad), {'out_of_tolerance_nodes': sorted(bad), 'approved_clock_skew_seconds': tolerance,
        'evidence_mode': 'externally_reviewed_measurements', 'native_clock_verified': False,
        'external_authenticity_independently_verified': False,
        'review_record_id': review['review_record_id'],
        'assurance': 'Verdict applies to externally supplied measurements and operator review; CSPM did not reproduce clock/reference verification.'}


def collect(raw, collections, scopes, cluster_id, captured_at):
    """Projection only; called after bounded native LIST inventories settle."""
    pages = {kind: [p for p in collections if p['type'] == kind and p['scope'] == '*']
             for kind in ('node', 'namespace')}
    try:
        if raw is None or scopes != ['*']:
            raise ValueError('clock measurement input or full cluster scope missing')
        if any(len(p) != 1 or p[0]['status'] not in ('collected', 'empty') for p in pages.values()):
            raise ValueError('clock native identity inventories incomplete')
        nodes, namespaces = (pages[k][0]['items'] for k in ('node', 'namespace'))
        validate_measurements(raw['review'], raw['observations'], nodes, namespaces, cluster_id, captured_at)
        rows = [{**deepcopy(row), 'source_operation': SOURCE,
                 'provenance': {'cluster_id': cluster_id, 'source': SOURCE,
                                'native_clock_verified': False, 'external_authenticity_independently_verified': False}}
                for row in raw['observations']]
        return {'type': 'node_clock', 'scope': '*', 'service': 'external_measurement',
                'status': 'collected', 'items': rows}, deepcopy(raw['review'])
    except (ValueError, KeyError, TypeError) as exc:
        return {'type': 'node_clock', 'scope': '*', 'service': 'external_measurement',
                'status': 'not_collected', 'items': [],
                'error': {'code': 'external_clock_measurement_unavailable'}}, None
