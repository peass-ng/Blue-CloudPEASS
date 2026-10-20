"""Native Workbench configuration checks, independent of customer exceptions."""
from copy import deepcopy
import re

from .facts import Unavailable, get, guard

PREFIX = 'gcp.review.workbench.'
STATES = frozenset({'STARTING', 'PROVISIONING', 'ACTIVE', 'STOPPING', 'STOPPED',
                    'DELETED', 'UPGRADING', 'INITIALIZING', 'SUSPENDING', 'SUSPENDED'})


def _subject(item, index):
    guard(item)
    name, state = get(item, 'name', str), get(item, 'state', str)
    scope = get(index, 'context.scope', str)
    if get(index, 'context.provider', str) != 'gcp' or not re.fullmatch(
            re.escape(scope) + r'/locations/[a-z0-9-]+/instances/[A-Za-z0-9_-]+', name):
        raise Unavailable('Workbench identity is outside the evaluated project')
    if state not in STATES:
        raise Unavailable('unrecognized Workbench state')
    return name, state


def _full(item, index):
    provenance = item.get('_provenance', {})
    return (provenance.get('representation') == 'full'
            and provenance.get('scope') == index['context']['scope']
            and bool(provenance.get('source_requests')))


def evaluate(item, index, *, root_access=False):
    name, state = _subject(item, index)
    if state == 'DELETED':
        return 'NOT_APPLICABLE', {'observed': 'The Workbench instance is deleted.'}
    setup = get(item, 'gceSetup', dict)
    if root_access:
        metadata = (get(item, 'gceSetup.metadata', dict)
                    if 'metadata' in setup or 'metadata' in setup.get('_coverage', {}) else None)
        if metadata is None:
            if not _full(item, index):
                raise Unavailable('Workbench metadata was not fully collected')
            metadata = {}
        if ('notebook-disable-root' not in metadata
                and 'notebook-disable-root' not in metadata.get('_coverage', {})):
            if not _full(item, index):
                raise Unavailable('Workbench root-access metadata was not fully collected')
            value = 'false'
        else:
            value = get(item, 'gceSetup.metadata.notebook-disable-root', str)
        if value not in {'true', 'false'}:
            raise Unavailable('unrecognized Workbench root-access metadata value')
        disabled = value == 'true'
        observed = ('Workbench notebook root access is disabled.' if disabled else
                    'Workbench notebook root access is enabled.')
        field = 'gceSetup.metadata.notebook-disable-root'
    else:
        if 'disablePublicIp' not in setup and 'disablePublicIp' not in setup.get('_coverage', {}):
            if not _full(item, index):
                raise Unavailable('Workbench public-IP setting was not fully collected')
            disabled = False
        else:
            disabled = get(item, 'gceSetup.disablePublicIp', bool)
        observed = ('The Workbench instance disables public IP assignment.' if disabled else
                    'The Workbench instance permits public IP assignment; this does not prove internet reachability.')
        field = 'gceSetup.disablePublicIp'
    return ('PASS' if disabled else 'FAIL'), {'observed': observed, 'instance': name,
                                             'setting': field, 'disabled': disabled}


def public_ip(item, index):
    return evaluate(item, index)


def root_access(item, index):
    return evaluate(item, index, root_access=True)


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    definitions = [
        ('public_ip_disabled', public_ip, 'network', 'Workbench instance disables public IP assignment',
         'Disable public IP assignment and use the private access path needed by notebook users.'),
        ('root_access_disabled', root_access, 'least_privilege', 'Workbench notebook root access is disabled',
         'Set notebook-disable-root to true unless notebook users need root access.'),
    ]
    existing = {check.id for check in CHECKS}
    for suffix, function, category, title, action in definitions:
        cid = PREFIX + suffix
        if cid in existing:
            continue
        register(cid, 'gcp', category, 'workbench_instance', title, 'medium',
                 'security_configuration', action)(function)
        good = {'name': 'projects/review/locations/us-central1-a/instances/notebook',
                'state': 'ACTIVE', 'gceSetup': {'disablePublicIp': True,
                                             'metadata': {'notebook-disable-root': 'true'}}}
        bad = deepcopy(good)
        if suffix == 'public_ip_disabled':
            bad['gceSetup']['disablePublicIp'] = False
        else:
            bad['gceSetup']['metadata']['notebook-disable-root'] = 'false'
        CASES[cid] = {'pass': good, 'fail': bad, 'missing': {}, 'malformed': None,
                      'index': {'context': {'provider': 'gcp', 'scope': 'projects/review'}}}
