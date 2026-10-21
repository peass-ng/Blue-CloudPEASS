"""Exact workload to ECR package-secret association; opt-in selected targets only."""
from copy import deepcopy
import hashlib
import json
from weakref import WeakValueDictionary
from peaso.secret_evidence import reuse_image_layer

from peaso.aws_image_selection_20261021 import selections
from .aws_image_vulnerability_native_20261021 import Reader
from .aws_package_content_indicators import PROFILE, OCI, DOCKER

CHECK = 'aws.review.workload.selected_image_secret_indicators'
ENABLE = 'content_secret_scans'
OPTION = 'selected_aws_workload_image_secrets'
KIND = 'aws_selected_workload_image_secrets'
GRANT = '_aws_workload_image_secret_grant'
_SEAL = object()
_ISSUED = WeakValueDictionary()


class _Grant:
    __slots__ = ('seal', 'scopes', 'targets', '__weakref__')
    def __init__(self, scopes, targets):
        self.seal, self.scopes = _SEAL, tuple(scopes)
        self.targets = hashlib.sha256(json.dumps(targets, sort_keys=True).encode()).hexdigest()


def issue_engine_grant(options, scopes, named):
    prior = options.pop(GRANT, None)
    if type(prior) is _Grant:
        _ISSUED.pop(id(prior), None)
    targets = selected(options, scopes, named)
    if not targets:
        return
    token = _Grant(scopes, targets)
    _ISSUED[id(token)] = token
    options[GRANT] = token


def authorize_collector(options, scopes):
    token = options.pop(GRANT, None)
    if token is None:
        return []
    targets = selected(options, scopes, [CHECK])
    if (type(token) is not _Grant or _ISSUED.get(id(token)) is not token
            or token.seal is not _SEAL or token.scopes != tuple(scopes)
            or token.targets != hashlib.sha256(json.dumps(targets, sort_keys=True).encode()).hexdigest()):
        raise ValueError('selected_workload_image_secret_grant_required')
    _ISSUED.pop(id(token))
    return targets


class _PinnedSession:
    """Keep the existing package projection on the native fixed AWS endpoint."""
    def __init__(self, session, config):
        self.session, self.config = session, config

    def client(self, service, *, region_name, config=None):
        return self.session.client(service, region_name=region_name, config=self.config)


def selected(options, scopes, named):
    """Call before credentials; a generic ECR or S3 selection grants nothing."""
    if type(options) is not dict or options.get(ENABLE) is not True or CHECK not in named:
        return []
    targets = selections({'image_vulnerability_scans': True,
        'selected_aws_image_vulnerabilities': options.get(OPTION)}, scopes)
    if len(targets) > 4 or any(not any(k in t for k in
            ('function_arn', 'task_definition_arn', 'job_definition_arn')) for t in targets):
        raise ValueError('exact_workload_target_required')
    return targets


def collect_scope(requests, session, account, region, targets, *, named):
    """Return typed safe package markers; raw SDK image bytes stay in projection."""
    scope = account + '/' + region
    options = {ENABLE: getattr(requests, ENABLE, False), OPTION: targets}
    authorized = selected(options, [scope], named) if all(t.get('scope') == scope for t in targets) else []
    if not authorized:
        return []
    rows = []
    reader = Reader(requests, session, account, region)
    pinned_session = _PinnedSession(session, reader.config)
    try:
        try:
            reader.caller()
        except Exception as exc:
            if getattr(exc, 'code', None) in ('collection_cancelled', 'deadline_exceeded', 'intentional_scan_deadline'):
                raise
            return [{'selection': deepcopy(t), 'binding_before': None, 'binding_after': None,
                'image': None, 'source': None, 'complete': False} for t in authorized]
        for target in authorized:
            source = None
            first, second, image = None, None, None
            try:
                repo, digest, _, first = reader.reference(target)
                image = {'repository_name': repo, 'image_digest': digest}
                image_request = {'_metadata_profile': PROFILE, 'registryId': account,
                    'repositoryName': repo, 'imageIds': [{'imageDigest': digest}]}
                # ECR documents only leaf values for acceptedMediaTypes. An exact
                # ECS/Batch parent digest may resolve to an OCI index when omitted.
                if 'function_arn' in target:
                    image_request['acceptedMediaTypes'] = [OCI, DOCKER]
                source = requests.detail(pinned_session, 'ecr', region, 'batch_get_image',
                    **image_request)
                later_repo, later_digest, _, second = reader.reference(target)
                if (later_repo, later_digest) != (repo, digest):
                    second = None
            except Exception as exc:
                if getattr(exc, 'code', None) in ('collection_cancelled', 'deadline_exceeded', 'intentional_scan_deadline'):
                    raise
            rows.append({'selection': deepcopy(target), 'binding_before': deepcopy(first),
                'binding_after': deepcopy(second),
                'image': image,
                'source': deepcopy(source) if type(source) is dict else None,
                'complete': first is not None and first == second and type(source) is dict
                    and source.get('collection_status') == 'collected'})
    finally:
        closed = reader.close()
        if not closed:
            for row in rows:
                row['complete'] = False
    return rows


def collect_collection(requests, session, identity, region, targets):
    from .aws import ReadResult
    scope = identity['Account'] + '/' + region
    selected_targets = [t for t in targets if t['scope'] == scope]
    if not selected_targets:
        return ReadResult([], 'empty')
    rows = collect_scope(requests, session, identity['Account'], region,
        selected_targets, named=[CHECK])
    items = []
    for row in rows:
        target = row['selection']
        asset = target.get('function_arn', target.get('task_definition_arn', target.get('job_definition_arn')))
        suffix = target.get('container_name', target.get('node_range', 'image'))
        resource = asset + '#' + suffix
        # The existing package scanner records the ECR origin. Join its verified
        # layer observations to this exact native workload finding as well.
        if row.get('binding_before') is not None and type(row.get('source')) is dict:
            marker = row['source'].get('PackageSecretIndicators') or {}
            for reference in marker.get('References', []):
                if type(reference) is dict and reference.get('Leaks'):
                    reuse_image_layer(reference['Leaks'], resource_id=resource, scope=scope,
                        layer=reference['LayerDigest'], image_digest=row['image']['image_digest'])
        items.append({'id': resource, 'WorkloadImageSecretReview': row})
    return ReadResult(items, 'collected' if all(r['complete'] for r in rows) else 'partial',
        None if all(r['complete'] for r in rows) else {'code': 'selected_image_secret_content_incomplete'})


def attach_metadata(metadata, targets):
    if targets:
        metadata[OPTION] = deepcopy(targets)


def disabled_snapshot(scopes):
    from peaso.snapshot import make_snapshot
    return make_snapshot('aws', list(scopes), [{'type': KIND, 'scope': scope,
        'service': 'ecr', 'status': 'not_collected', 'items': [],
        'error': {'code': 'selected_workload_image_secret_scan_disabled'}} for scope in scopes],
        metadata={'collection': 'read-only', 'content_secret_scans': False})
