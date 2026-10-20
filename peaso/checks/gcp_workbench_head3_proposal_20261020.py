"""Unregistered Workbench v2 declaration proposals from Prowler HEAD.

No registration, cloud reads, runtime gates or compliance mappings are installed.
Predicates consume the ordinary complete project-scoped Workbench inventory.
"""
import re

from .facts import Unavailable, complete_items, get, guard
from peaso.collectors.gcp_workbench_head3_projection_20261020 import KEY, supported_schedule

PREFIX = 'gcp.review.workbench.'
KIND = 'workbench_instance'
STATES = frozenset({'STARTING', 'PROVISIONING', 'ACTIVE', 'STOPPING', 'STOPPED',
                   'DELETED', 'UPGRADING', 'INITIALIZING', 'SUSPENDING', 'SUSPENDED'})


def _request_ids(value):
    return (isinstance(value, list) and 0 < len(value) <= 10000
            and all(isinstance(ref, str) and 0 < len(ref) <= 256 for ref in value)
            and len(set(value)) == len(value))


def _subject(item, index):
    """Authenticate membership, complete collection, representation and scope."""
    guard(item)
    scope = get(index, 'context.scope', str)
    if (get(index, 'context.provider', str) != 'gcp'
            or not re.fullmatch(r'projects/[A-Za-z0-9_-]+', scope)):
        raise Unavailable('Workbench project authority unavailable')
    envelopes = get(index, 'collections', dict).get(KIND)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('one complete Workbench collection required')
    envelope = envelopes[0]
    if (not isinstance(envelope, dict) or envelope.get('type') != KIND
            or envelope.get('scope') != scope or envelope.get('service') != 'notebooks'
            or envelope.get('status') != 'collected'
            or envelope.get('coverage_status') != 'collected'
            or 'error' in envelope or not _request_ids(envelope.get('source_requests'))):
        raise Unavailable('Workbench collection unavailable or incomplete')
    rows = complete_items(index, KIND)
    if (not rows or rows != envelope.get('items') or sum(row == item for row in rows) != 1):
        raise Unavailable('Workbench resource is not uniquely in the collection')
    pattern = re.escape(scope) + r'/locations/[a-z0-9-]+/instances/[A-Za-z0-9_-]+'
    names = set()
    for row in rows:
        name = get(row, 'name', str)
        proof = get(row, '_provenance', dict)
        if (not re.fullmatch(pattern, name) or name in names
                or proof.get('scope') != scope or proof.get('representation') != 'full'
                or not _request_ids(proof.get('source_requests'))
                or not set(proof['source_requests']) <= set(envelope['source_requests'])):
            raise Unavailable('Workbench identity or full native representation unavailable')
        names.add(name)
    wrappers = get(index, KIND, list)
    if any(get(row, 'scope', str) != scope or get(row, 'type', str) != KIND
           or row.get('provider', 'gcp') != 'gcp' for row in wrappers):
        raise Unavailable('Workbench resource wrapper is foreign')
    state = get(item, 'state', str)
    if state not in STATES:
        raise Unavailable('Workbench state is unrecognized')
    return get(item, 'name', str), state


def _metadata_value(item, key, default):
    setup = get(item, 'gceSetup', dict)
    if 'metadata' in setup or 'metadata' in setup.get('_coverage', {}):
        metadata = get(item, 'gceSetup.metadata', dict)
    else:
        metadata = {}
    if key in metadata or key in metadata.get('_coverage', {}):
        return get(metadata, key, str)
    # systemMetadata is a separate output field, not a proven alias. Do not
    # mistake an observed system-only setting for an unset custom metadata key.
    if 'systemMetadata' in setup or 'systemMetadata' in setup.get('_coverage', {}):
        system = get(item, 'gceSetup.systemMetadata', dict)
        if key in system or key in system.get('_coverage', {}):
            raise Unavailable('system-only Workbench setting requires separate evidence')
    return default


def _evaluate(item, index, suffix):
    unknown = ('UNKNOWN', {'observed': 'The Workbench setting could not be established from complete native configuration.'})
    try:
        name, state = _subject(item, index)
        if state == 'DELETED':
            return 'NOT_APPLICABLE', {'observed': 'The Workbench instance is deleted.'}
        if suffix == 'auto_upgrade_schedule_declared':
            value = _metadata_value(item, KEY, '')
            if supported_schedule(value) is None:
                return unknown
            declared = value != ''
            observed = ('The Workbench instance declares an upgrade schedule in the supported cron format.' if declared
                        else 'The Workbench instance has no automatic upgrade schedule declared.')
            observed += ' Upgrade execution and patch status were not established.'
            return ('PASS' if declared else 'FAIL'), {
                'observed': observed, 'instance': name,
                'setting': 'gceSetup.metadata.' + KEY, 'schedule_declared': declared,
            }
        key, label = {
            'terminal_access_disabled': ('notebook-disable-terminal', 'terminal access'),
            'file_download_disabled': ('notebook-disable-downloads', 'file downloads'),
        }[suffix]
        value = _metadata_value(item, key, 'false')
        if value not in ('true', 'false'):
            return unknown
        disabled = value == 'true'
        observed = 'Workbench ' + label + (' is disabled.' if disabled else ' is enabled.')
        if suffix == 'file_download_disabled':
            observed = 'Workbench file downloads are ' + ('disabled.' if disabled else 'enabled.')
        return ('PASS' if disabled else 'FAIL'), {
            'observed': observed, 'instance': name,
            'setting': 'gceSetup.metadata.' + key, 'disabled': disabled,
        }
    except (Unavailable, KeyError, TypeError, ValueError, AttributeError):
        return unknown


def terminal_access_disabled(item, index):
    return _evaluate(item, index, 'terminal_access_disabled')


def file_download_disabled(item, index):
    return _evaluate(item, index, 'file_download_disabled')


def auto_upgrade_schedule_declared(item, index):
    return _evaluate(item, index, 'auto_upgrade_schedule_declared')


EVALUATORS = {
    PREFIX + 'terminal_access_disabled': terminal_access_disabled,
    PREFIX + 'file_download_disabled': file_download_disabled,
    PREFIX + 'auto_upgrade_schedule_declared': auto_upgrade_schedule_declared,
}
