"""Named-check grant for explicit ECR Public image reads."""
from copy import deepcopy
from contextlib import ExitStack
from hashlib import sha256
import json
from weakref import WeakValueDictionary

from peaso.aws_ecr_public_selection_20261021 import (KIND, OPTION, SECRET_CHECK,
    VULN_CHECK, selected_targets, enabled)

GRANT = '_aws_ecr_public_image_grant'
_SEAL = object()
_ISSUED = WeakValueDictionary()


def _hash(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class _Grant:
    __slots__ = ('seal','scopes','targets','secret','vuln','__weakref__')
    def __init__(self, scopes, targets, secret, vuln):
        self.seal, self.scopes, self.targets = _SEAL, tuple(scopes), _hash(targets)
        self.secret, self.vuln = secret, vuln


def issue_engine_grant(options, scopes, named):
    previous = options.pop(GRANT, None)
    if type(previous) is _Grant:
        _ISSUED.pop(id(previous), None)
    targets = selected_targets(options, scopes)
    secret, vuln = enabled(options, named)
    if not (secret or vuln):
        return
    if not targets:
        raise ValueError('exact_ecr_public_targets_required')
    grant = _Grant(scopes, targets, secret, vuln)
    _ISSUED[id(grant)] = grant
    options[GRANT] = grant


def authorize_collector(options, scopes):
    grant = options.pop(GRANT, None)
    targets = selected_targets(options, scopes)
    if grant is None:
        return [], False, False
    if (type(grant) is not _Grant or _ISSUED.get(id(grant)) is not grant
            or grant.seal is not _SEAL or grant.scopes != tuple(scopes)
            or grant.targets != _hash(targets) or not (grant.secret or grant.vuln)):
        raise ValueError('ecr_public_named_grant_required')
    _ISSUED.pop(id(grant))
    return targets, grant.secret, grant.vuln


def disabled_snapshot(scopes):
    from peaso.snapshot import make_snapshot
    return make_snapshot('aws', list(scopes), [{'type':KIND,'scope':scope,'service':'ecr-public',
        'status':'not_collected','items':[], 'error':{'code':'selected_ecr_public_scan_disabled'}} for scope in scopes],
        metadata={'collection':'read-only','content_secret_scans':False,'image_vulnerability_scans':False})


def collect_scope(requests,session,identity,region,targets,*,secret,vuln):
    from .aws_ecr_public_image_native_20261021 import collect_scope as native
    from . import selected_image_trivy_database_20261021 as database
    from .aws import ReadResult
    with ExitStack() as lease_stack:
        cache = database.acquire(lease_stack, enabled=vuln, cancel=requests.check_deadline)
        result = native(requests, session, identity, region, targets,
            secret_enabled=secret, vuln_enabled=vuln and cache is not None,
            trivy_db=cache)
    if vuln and cache is None:
        return ReadResult(result.items, 'partial', {'code':'trivy_database_unavailable'})
    return result


def attach_metadata(metadata,targets,secret,vuln):
    if targets:
        metadata[OPTION] = deepcopy(targets)
        metadata[KIND+'_secret_authorized'] = secret
        metadata[KIND+'_vulnerability_authorized'] = vuln
