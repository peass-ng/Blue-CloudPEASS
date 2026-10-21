"""Selected App Engine Flex Version GET to immutable OCI content association."""
from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import quote

from peaso import gcp_appengine_flex_image_selection_20261021 as selection
from peaso import oci_index_20261021 as oci_index
from . import gcp_image_secret_indicators as image
from .gcp_image_stream_inspection_20261021 import inspect_image, _interrupt
from .gcp_image_stream_reader_20261021 import Reader
from .gcp_workerpool_image_native_20261021 import Capture, _session

SCHEMA = 'gcp-appengine-flex-selected-version-image-v1'
VERSION_FIELDS = 'name,id,env,createTime,deployment(container(image))'
PROJECT_FIELDS = 'name,projectId,state'
REPO_FIELDS = 'name,format,mode,updateTime'
IMAGE_FIELDS = 'name,uri,mediaType,updateTime'


def identity(target):
    return 'appengine-flex-image:' + hashlib.sha256(json.dumps(target, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def requests_for(target, scope):
    uri, repo, digest, image_name = image.parse_image_uri(target['immutable_reference'])
    if not repo.startswith(scope + '/') or uri != 'https://' + target['immutable_reference']:
        raise ValueError('foreign_image')
    return [('https://cloudresourcemanager.googleapis.com/v3/' + scope, PROJECT_FIELDS),
            ('https://artifactregistry.googleapis.com/v1/' + repo, REPO_FIELDS),
            ('https://artifactregistry.googleapis.com/v1/' + repo + '/dockerImages/' + quote(image_name, safe=''), IMAGE_FIELDS)]


def bind_version(target, raw):
    match = selection.VERSION.fullmatch(target['version_name'])
    if type(raw) is not dict or set(raw) - {'name', 'id', 'env', 'createTime', 'deployment'}:
        raise ValueError('version_fields_unavailable')
    deployment = raw.get('deployment')
    container = deployment.get('container') if type(deployment) is dict and set(deployment) == {'container'} else None
    if (not match or raw.get('name') != target['version_name'] or raw.get('id') != match[3]
            or raw.get('env') != 'flex' or type(raw.get('createTime')) is not str
            or len(raw['createTime']) > 64 or not raw['createTime'].endswith('Z')
            or type(container) is not dict
            or set(container) != {'image'} or container['image'] != target['immutable_reference']):
        raise ValueError('version_identity_or_digest_changed')
    return {'name': raw['name'], 'id': raw['id'], 'env': raw['env'], 'createTime': raw['createTime'],
            'immutable_reference': container['image'], 'runtime_image_proven': False}


def bind_registry(target, scope, bodies):
    project, repository, docker_image = bodies
    uri, repo, digest, image_name = image.parse_image_uri(target['immutable_reference'])
    if (type(project) is not dict or project.get('projectId') != scope.split('/')[1]
            or project.get('state') != 'ACTIVE' or type(project.get('name')) is not str
            or re.fullmatch(r'projects/[0-9]+', project['name']) is None
            or type(repository) is not dict or repository.get('name') != repo
            or repository.get('format') != 'DOCKER' or repository.get('mode') not in (None, 'STANDARD_REPOSITORY')
            or type(docker_image) is not dict or docker_image.get('uri') != target['immutable_reference']
            or docker_image.get('mediaType') not in oci_index.ALL_MANIFEST_TYPES):
        raise ValueError('native_image_owner_unavailable')
    row = {**docker_image, 'repository': repo, 'digest': digest}
    if image.bind_image(row, scope, [repository], [project]) != (uri, repo, digest):
        raise ValueError('native_image_owner_unavailable')
    return row


def inspect_selected(target, scope, *, version_get, capture, reader,
                     secret_enabled=True, vuln_enabled=False, trivy_collect=None,
                     match_callback=None):
    """Bind Version, project/repository/image, content, then all owners again."""
    row = {'selection': deepcopy(target), 'status': 'UNKNOWN', 'complete': False,
           'reason': 'native_read_unavailable', 'association_revalidated': False,
           'declaration': None, 'content': {'complete': False, 'leaks': []},
           'vulnerability': None, 'source_requests': [], 'metadata_captures': []}
    capture_start = len(capture.captures)
    record_start = len(capture.records)
    image_start = len(reader.request_ids)
    version_refs = []
    try:
        raw, ref = version_get(target)
        version_refs.append(ref)
        declared = bind_version(target, raw)
        reqs = requests_for(target, scope)
        before = [capture.get(*req) for req in reqs]
        owner = bind_registry(target, scope, before)
        row['declaration'] = declared
        if secret_enabled:
            row['content'] = inspect_image(owner, scope, [before[1]], [before[0]], reader,
                                           match_callback=match_callback,
                                           capture_resource_id=identity(target))
        if vuln_enabled:
            if trivy_collect is None:
                raise ValueError('trivy_capability_unavailable')
            row['vulnerability'] = trivy_collect(target['immutable_reference'], scope)
        after = [capture.get(*req) for req in reqs]
        bind_registry(target, scope, after)
        raw_after, ref_after = version_get(target)
        version_refs.append(ref_after)
        if bind_version(target, raw_after) != declared or before != after:
            raise ValueError('source_metadata_changed')
        row['association_revalidated'] = True
        secret_complete = secret_enabled and row['content'].get('complete') is True
        vuln = row['vulnerability']
        vuln_complete = vuln_enabled and type(vuln) is dict and vuln.get('complete') is True
        row['complete'] = (not secret_enabled or secret_complete) and (not vuln_enabled or vuln_complete)
        leaks = row['content'].get('leaks') if secret_enabled else []
        vuln_hit = type(vuln) is dict and vuln.get('status') == 'FAIL'
        row['status'] = 'FAIL' if leaks or vuln_hit else 'PASS' if row['complete'] else 'UNKNOWN'
        row['reason'] = 'complete' if row['complete'] else 'image_content_incomplete'
    except Exception as exc:
        if _interrupt(exc):
            raise
        row['reason'] = str(exc) if type(exc) is ValueError and str(exc) in {
            'version_fields_unavailable', 'version_identity_or_digest_changed',
            'native_image_owner_unavailable', 'source_metadata_changed',
            'trivy_capability_unavailable'} else 'native_read_unavailable'
        row['complete'] = False
        if not row['association_revalidated']:
            row['status'] = 'UNKNOWN'
    finally:
        row['version_source_requests'] = version_refs[:]
        row['secret_image_source_requests'] = reader.request_ids[image_start:]
        extra = row['vulnerability'].get('source_requests', []) if type(row['vulnerability']) is dict else []
        row['source_requests'] = (version_refs + [r['id'] for r in capture.records[record_start:]]
                                  + reader.request_ids[image_start:] + extra)
        row['metadata_captures'] = deepcopy(capture.captures[capture_start:])
    return row


def collect_native(transport, *, scope, selectors, enabled=False, version_get,
                   secret_enabled=True, vuln_enabled=False,
                   metadata_session=None, image_session=None, trivy_collect=None,
                   match_callback=None):
    result = {'schema': SCHEMA, 'scope': scope, 'rows': [], 'source_requests': [],
              'status': 'UNKNOWN', 'complete': False}
    if enabled is not True:
        return result
    targets = selection.selected({selection.OPTION: selectors}, [scope],
        [selection.SECRET_CHECK if secret_enabled else selection.VULN_CHECK])
    metadata_session = metadata_session or _session()
    image_session = image_session or _session()
    capture = Capture(transport, metadata_session, scope)
    reader = Reader(transport, session=image_session)
    reader.end = min(reader.end, capture.end)
    try:
        for target in targets:
            result['rows'].append(inspect_selected(target, scope, version_get=version_get,
                capture=capture, reader=reader, secret_enabled=secret_enabled,
                vuln_enabled=vuln_enabled, trivy_collect=trivy_collect,
                match_callback=match_callback))
        result['complete'] = all(r['complete'] for r in result['rows'])
        result['status'] = 'FAIL' if any(r['status'] == 'FAIL' for r in result['rows']) else 'PASS' if result['complete'] else 'UNKNOWN'
    finally:
        result['source_requests'] = deepcopy(capture.records) + [deepcopy(r) for r in getattr(transport, 'evidence', [])
            if r.get('id') in reader.request_ids]
        for session in (metadata_session, image_session):
            try: session.close()
            except Exception:
                result['complete'] = False
                if result['status'] != 'FAIL': result['status'] = 'UNKNOWN'
                for row in result['rows']:
                    row['complete'] = False
                    if row['status'] != 'FAIL':
                        row['status'] = 'UNKNOWN'
                        row['content']['complete'] = False
                        vulnerability = row.get('vulnerability')
                        if type(vulnerability) is dict and type(vulnerability.get('record')) is dict:
                            vulnerability['record']['complete'] = False
    return result
