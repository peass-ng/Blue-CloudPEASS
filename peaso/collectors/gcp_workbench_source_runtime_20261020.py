"""Engine-only admission seam for the sealed selected Workbench source reader."""
import json
from peaso.secret_scanning import _fingerprint
from . import gcp_workbench_referenced_source_20261020 as source
from . import gcp_dataproc_source_runtime_20261020 as dataproc

SPEC = source.PROFILES['instance']
KIND, CHECK = SPEC['kind'], SPEC['check']
KINDS, CHECKS = frozenset({KIND}), (CHECK,)
NAMED = '_workbench_source_named_checks'
GRANT = '_workbench_source_engine_grant'
_SEAL = object()


class _Grant:
    __slots__ = ('seal', 'scopes', 'selection')

    def __init__(self, scopes, targets):
        self.seal = _SEAL
        self.scopes = tuple(scopes)
        self.selection = _fingerprint(json.dumps(targets, sort_keys=True))


def preflight(options, scopes, named=()):
    """Validate supplied selectors even when disabled, before credential construction."""
    selected = CHECK in named
    try:
        targets = source.selected_targets({**options,
            '_content_secret_scan_kinds': [KIND] if selected else [],
            NAMED: [CHECK] if selected else []}, scopes)
    except (source.Incomplete, UnicodeError, TypeError, ValueError):
        raise ValueError('Selected Workbench sources require 1-4 exact scoped instance/field/bucket/object/generation targets') from None
    if selected and options.get('content_secret_scans') is True and not targets:
        raise ValueError('Selected Workbench source check requires exact startup source targets')
    return targets


def issue_engine_grant(options, scopes, named=()):
    """Called by the engine with actual selected explicit IDs, never connector claims."""
    options.pop(GRANT, None)
    options[NAMED] = []
    targets = preflight(options, scopes, named)
    if CHECK in named and options.get('content_secret_scans') is True:
        options[GRANT] = _Grant(scopes, targets)


def authorize_collector(options, scopes):
    """Consume the in-memory engine grant; JSON/private named strings cannot grant IO."""
    token = options.pop(GRANT, None)
    targets = preflight(options, scopes)
    permitted = (type(token) is _Grant and token.seal is _SEAL and token.scopes == tuple(scopes)
                 and token.selection == _fingerprint(json.dumps(targets, sort_keys=True))
                 and options.get('content_secret_scans') is True)
    options[NAMED] = [CHECK] if permitted else []
    incoming = options.get('_content_secret_scan_kinds')
    incoming = incoming if isinstance(incoming, list) else []
    options['_content_secret_scan_kinds'] = [k for k in incoming if k != KIND or permitted]
    return KINDS if permitted and KIND in options['_content_secret_scan_kinds'] else frozenset()


def jobs(collector, scope):
    return source.jobs(collector, scope, 'instance')


def preserve_capture(item, raw, transport):
    """Carry genuine producer provenance through the generic envelope boundary."""
    state = getattr(transport, '_workbench_source_state', {})
    produced = state.get('items', {}).get(raw.get('name'))
    if (produced is not None and raw.get(source.MARKER) == produced.get(source.MARKER)
            and raw.get('_provenance') == produced.get('_provenance')
            and state.get('capture') == produced['_provenance'].get('capture')):
        item['_provenance']['capture'] = produced['_provenance']['capture']


def final_snapshot(collector, snapshot):
    """Exchange the active match union before the sealed finalizer clears its state."""
    values = set(source.redaction_values(collector.transport)) | set(dataproc.source.redaction_values(collector.transport))
    # Shared redaction handles string keys; retained collector keys are tuples.
    # Replace a changed tuple key with a unique opaque key before cleanup.
    cleaned = {}
    for key, value in collector.collections.items():
        safe = source.redact_matches(list(key) if isinstance(key, tuple) else key, values)
        if isinstance(key, tuple) and safe != list(key):
            key = ('redacted-collection', _fingerprint(json.dumps(key)))
        elif not isinstance(key, tuple):
            key = safe
        cleaned[key] = source.redact_matches(value, values)
    collector.collections = cleaned
    state = getattr(collector.transport, '_dataproc_source_state', None)
    if state is not None:
        state['redactions'].update(values)
    return source.final_snapshot(collector, snapshot, redactions=values)
