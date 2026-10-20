"""Unregistered pure successor: require Dataflow closing request bindings.

The predecessor still owns native/engine/leak validation. This adds equality
of real opening/closing request hashes, not signed snapshot authentication or
protection against an actor fabricating an entire capture.
"""
from copy import deepcopy
from . import gcp_dataflow_referenced_source_20261020 as predecessor

DECLARATION = deepcopy(predecessor.DECLARATION)
PAIRS = ((0, 8), (1, 6), (2, 7), (3, 5))


def _requests_bound(item, capture):
    try:
        refs = item['requests']; receipts = capture['receipts']
        if (not isinstance(refs, list) or len(refs) != 9 or len(set(refs)) != 9
                or not isinstance(receipts, list) or not 9 <= len(receipts) <= predecessor.source.MAX_CALLS):
            return False
        ledger = {r['id']: r for r in receipts}
        if len(ledger) != len(receipts):
            return False
        own = [ledger[r] for r in refs]
        return ([r['operation'] for r in own] == list(predecessor.source.OPERATIONS)
                and all(own[a]['request'] == own[b]['request'] for a, b in PAIRS))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _unknown():
    return 'UNKNOWN', dict(complete=False,
        observed='The selected current referenced package has unavailable or inconsistent opening and closing request evidence.')


def evaluate(item, capture):
    """Exact predecessor verdicts plus closing equality; no mutation or IO."""
    if not _requests_bound(item, capture):
        return _unknown()
    status, details = predecessor.evaluate(item, capture)
    if details['complete'] and not all(_requests_bound(other, capture) for other in capture['items']):
        if status == 'PASS':
            return _unknown()
        details = {**details, 'complete': False}
    return status, details


def validate_successor():
    """Explicit source attestation only; evaluate() performs no file reads."""
    import gzip
    import hashlib
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads(Path(__file__).with_suffix('.json').read_text())
    if receipt.get('registration') != 'unregistered_consumer_successor_only':
        raise ValueError('successor registration')
    for relative, expected in receipt['files'].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('successor source changed: ' + relative)
    archived = (root / receipt['predecessor']).resolve()
    if not archived.is_relative_to(root / 'peaso/checks') or receipt['predecessor'] not in receipt['files']:
        raise ValueError('predecessor archive outside reviewed package')
    baseline = json.loads(gzip.decompress(archived.read_bytes()))
    for relative, entry in baseline['sources'].items():
        raw = entry['content'].encode('utf-8')
        path = (root / relative).resolve()
        if (not path.is_relative_to(root) or len(raw) != entry['bytes']
                or hashlib.sha256(raw).hexdigest() != entry['sha256'] or path.read_bytes() != raw):
            raise ValueError('preserved predecessor changed: ' + relative)
    return deepcopy(receipt)
