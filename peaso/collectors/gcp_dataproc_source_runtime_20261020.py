"""Production planner seam for the immutable reviewed Dataproc source reader."""
from . import gcp_dataproc_referenced_source_secret_indicators as source

KINDS = frozenset(p['kind'] for p in source.PROFILES.values())
CHECKS = tuple(p['check'] for p in source.PROFILES.values())
NAMED = '_dataproc_source_named_checks'


def preflight(options, scopes, named=()):
    """All selectors validate before credentials; only exact named checks admit IO."""
    selected = [p for p in source.PROFILES.values() if p['check'] in named]
    try:
        targets = source.selected_targets({**options, '_content_secret_scan_kinds': [p['kind'] for p in selected]}, scopes)
    except source.Incomplete:
        raise ValueError('Selected Dataproc sources require exact scoped references and object generations') from None
    if options.get('content_secret_scans') is True:
        for profile, p in source.PROFILES.items():
            if p in selected and not any(t['profile'] == profile for t in targets):
                raise ValueError('Selected Dataproc profile requires an exact referenced source target')
    return targets


def authorize_collector(options, scopes):
    """Engine stamps named checks; inventory/private-kind input alone is excluded."""
    named = options.get(NAMED)
    named = [c for c in named if c in CHECKS] if isinstance(named, list) else []
    preflight(options, scopes, named)
    permitted = {p['kind'] for p in source.PROFILES.values() if p['check'] in named}
    incoming = options.get('_content_secret_scan_kinds')
    incoming = incoming if isinstance(incoming, list) else []
    options['_content_secret_scan_kinds'] = [k for k in incoming if k not in KINDS or k in permitted]
    return KINDS & set(options['_content_secret_scan_kinds']) if options.get('content_secret_scans') is True else frozenset()


def final_snapshot(collector, snapshot):
    """Scrub retained collector metadata too, before consuming the private union.

    The immutable reader owns export/transport/options redaction and final
    cleanup. Other content-reader match sets are neither consumed nor cleared.
    """
    values = source.redaction_values(collector.transport)
    collector.collections = source.redact_matches(collector.collections, values)
    return source.final_snapshot(collector, snapshot, redactions=values)
