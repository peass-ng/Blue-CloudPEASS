"""Pure Cloud Run v1 -> selected immutable image read plans.

Inputs are already collected native GET bodies indexed by their exact regional
request URLs, plus complete project/repository/DockerImage inventory rows. The
caller owns native provenance, completeness, request receipts and a consistent
capture window; dictionaries alone cannot establish those facts. No I/O, policy
imports, image reads or secret assessment occurs here. Any unsupported active
path rejects the whole plan. This covers an explicit service subset at capture
time, never all project workloads or all historical revisions.
"""
from copy import deepcopy
import re
from urllib.parse import unquote

SCHEMA = 'gcp-cloudrun-content-source-plan-v1'
MAX_SERVICES = 4
MAX_REVISIONS = 16
MAX_IMAGES = 4  # gcp_image_secret_indicators.MAX_IMAGES
SERVICE_FIELDS = 'metadata(name,namespace,uid,generation,deletionTimestamp),status(observedGeneration,conditions(type,status),traffic(revisionName,percent,tag,latestRevision))'
REVISION_FIELDS = 'metadata(name,namespace,uid,generation,labels,deletionTimestamp),spec(containers(image)),status(observedGeneration,imageDigest,conditions(type,status))'
API_REFERENCES = (
    'https://docs.cloud.google.com/run/docs/reference/rest/v1/namespaces.services',
    'https://docs.cloud.google.com/run/docs/reference/rest/v1/namespaces.revisions',
    'https://docs.cloud.google.com/run/docs/reference/rest/v1/TrafficTarget',
    'https://docs.cloud.google.com/run/docs/reference/rest/v1/namespaces.services/get',
    'https://docs.cloud.google.com/run/docs/reference/rest/v1/namespaces.revisions/get',
)
_NAME = r'[a-z][a-z0-9-]{0,62}'


def _require(ok, code):
    if not ok:
        raise ValueError(code)


def _selection(scope, services):
    _require(isinstance(scope, str) and re.fullmatch(r'projects/[a-z][a-z0-9-]*', scope),
             'native_project_id_scope_required')
    _require(isinstance(services, list) and 1 <= len(services) <= MAX_SERVICES
             and all(isinstance(s, str) for s in services), 'bounded_explicit_services_required')
    _require(len(set(services)) == len(services), 'duplicate_service_selection')
    for service in services:
        _require(re.fullmatch(re.escape(scope) + r'/locations/[a-z][a-z0-9-]*/services/' + _NAME, service),
                 'foreign_or_invalid_service_selection')
    return sorted(services)


def _base(service):
    parts = service.split('/')
    return ('https://' + parts[3] + '-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/'
            + parts[1])


def service_requests(scope, services):
    """Metadata-only first stage; execute GETs outside this module."""
    return [{'method': 'GET', 'url': _base(s) + '/services/' + s.rsplit('/', 1)[1],
             'scope': scope, 'params': {'fields': SERVICE_FIELDS}} for s in _selection(scope, services)]


def _generation(value):
    return (type(value) is int and value > 0 or isinstance(value, str)
            and re.fullmatch(r'[1-9][0-9]{0,19}', value) is not None)


def _ready(body, short, aliases):
    _require(isinstance(body, dict), 'native_response_missing')
    meta, status = body.get('metadata'), body.get('status')
    _require(isinstance(meta, dict) and meta.get('name') == short
             and isinstance(meta.get('namespace'), str) and meta['namespace'] in aliases and not meta.get('deletionTimestamp')
             and isinstance(status, dict), 'native_identity_or_deletion_mismatch')
    _require(isinstance(meta.get('uid'), str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', meta['uid']),
             'native_resource_uid_missing_or_malformed')
    _require(_generation(meta.get('generation')) and _generation(status.get('observedGeneration'))
             and str(meta['generation']) == str(status['observedGeneration']), 'native_reconciling')
    conditions = status.get('conditions')
    _require(isinstance(conditions, list) and all(isinstance(c, dict) for c in conditions)
             and [c.get('status') for c in conditions if c.get('type') == 'Ready'] == ['True'],
             'native_not_ready')
    return meta, status


def _aliases(scope, projects):
    _require(isinstance(projects, list) and all(isinstance(p, dict) for p in projects), 'native_project_rows_required')
    rows = [p for p in projects if p.get('projectId') == scope.split('/')[1]]
    _require(len(rows) == 1 and isinstance(rows[0].get('name'), str)
             and (rows[0]['name'] == scope or re.fullmatch(r'projects/[0-9]+', rows[0]['name'])),
             'native_project_join_incomplete')
    return {scope.split('/')[1], rows[0]['name'].split('/')[1]}


def _targets(status):
    traffic = status.get('traffic')
    _require(isinstance(traffic, list) and 1 <= len(traffic) <= 100, 'native_traffic_missing_or_bound')
    selected, tags, total = {}, set(), 0
    for target in traffic:
        _require(isinstance(target, dict) and isinstance(target.get('revisionName'), str)
                 and re.fullmatch(_NAME, target['revisionName']), 'native_traffic_revision_unresolved')
        percent, tag = target.get('percent', 0), target.get('tag', '')
        _require(type(percent) is int and 0 <= percent <= 100 and isinstance(tag, str)
                 and (not tag or re.fullmatch(_NAME, tag))
                 and (not tag or tag not in tags)
                 and type(target.get('latestRevision', False)) is bool, 'native_traffic_target_invalid')
        total += percent
        if tag:
            tags.add(tag)
        if percent > 0 or tag:
            info = selected.setdefault(target['revisionName'], {'percent': 0, 'tags': []})
            info['percent'] += percent
            if tag:
                info['tags'].append(tag)
    _require(total == 100 and 1 <= len(selected) <= MAX_REVISIONS, 'native_traffic_incomplete_or_bound')
    return selected


def revision_requests(scope, services, *, projects, service_reads):
    """Resolve every positive-traffic OR tagged revision from reconciled status."""
    aliases, result = _aliases(scope, projects), []
    _require(isinstance(service_reads, dict), 'native_service_reads_required')
    for request in service_requests(scope, services):
        service = request['url'].rsplit('/', 1)[1]
        _, status = _ready(service_reads.get(request['url']), service, aliases)
        for revision in sorted(_targets(status)):
            result.append({'method': 'GET', 'url': request['url'].rsplit('/services/', 1)[0] + '/revisions/' + revision,
                           'scope': scope, 'params': {'fields': REVISION_FIELDS}})
    _require(len(result) <= MAX_REVISIONS, 'active_revision_total_bound')
    return result


def _image(value, scope):
    from peaso.collectors.gcp_registry_image_uri import parse
    _require(isinstance(value, str), 'immutable_image_missing')
    try:
        uri, repo, digest, _ = parse(value)
    except ValueError:
        raise ValueError('immutable_artifact_image_required') from None
    _require(repo.startswith(scope + '/') and value == value.lower(), 'foreign_or_unsafe_image')
    return uri, repo, digest


def _bind_spec(image, uri):
    # A mutable spec is allowed only after status resolves the SAME image path.
    # Immutable specs must also match the exact resolved digest.
    _require(isinstance(image, str) and not image.startswith('https://'), 'revision_spec_image_invalid')
    resolved = uri.removeprefix('https://')
    if '@' in image:
        _require(image == resolved, 'revision_spec_digest_mismatch')
    else:
        _require(re.fullmatch(r'[^:@]+(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?', image)
                 and image.split(':', 1)[0] == resolved.split('@', 1)[0], 'revision_spec_image_path_mismatch')


def plan_sources(scope, services, *, projects, repositories, service_reads, revision_reads, image_rows):
    """Return reader-compatible rows and selection; ValueError means no plan.

    Call gcp_image_secret_indicators.bind_image/inspect_image with each image row
    and the same complete inventories. A plan is never
    content evidence: complete=False and content_status=not_inspected always.
    Multi-container v1 revisions are rejected because imageDigest binds only the
    singular container contract; no sidecar completeness can be inferred.
    """
    selected = _selection(scope, services)
    aliases = _aliases(scope, projects)
    requests = revision_requests(scope, selected, projects=projects, service_reads=service_reads)
    _require(isinstance(revision_reads, dict) and isinstance(repositories, list)
             and isinstance(image_rows, list) and all(isinstance(r, dict) for r in repositories + image_rows),
             'native_image_inventories_required')
    paths, images = [], {}
    for service in selected:
        short = service.rsplit('/', 1)[1]
        _, status = _ready(service_reads.get(_base(service) + '/services/' + short), short, aliases)
        for revision, route in sorted(_targets(status).items()):
            url = _base(service) + '/revisions/' + revision
            raw = revision_reads.get(url)
            meta, revision_status = _ready(raw, revision, aliases)
            _require(isinstance(meta.get('labels'), dict)
                     and meta['labels'].get('serving.knative.dev/service') == short, 'native_revision_service_mismatch')
            containers = raw.get('spec', {}).get('containers') if isinstance(raw.get('spec'), dict) else None
            _require(isinstance(containers, list) and len(containers) == 1 and isinstance(containers[0], dict),
                     'multi_container_or_missing_container_unsupported')
            uri, repo, digest = _image(revision_status.get('imageDigest'), scope)
            _bind_spec(containers[0].get('image'), uri)
            matches = [r for r in repositories if r.get('name') == repo]
            _require(len(matches) == 1 and matches[0].get('format') == 'DOCKER', 'native_repository_join_incomplete')
            rows = [r for r in image_rows if r.get('uri') == uri]
            _require(len(rows) == 1, 'native_docker_image_missing_or_duplicate')
            row = rows[0]
            name = row.get('name')
            from peaso.collectors.gcp_registry_image_uri import parse
            _require(row.get('repository') == repo and row.get('digest') == digest
                     and isinstance(name, str) and name.startswith(repo + '/dockerImages/')
                     and unquote(name[len(repo + '/dockerImages/'):]) == parse(uri)[3],
                     'native_docker_image_binding_mismatch')
            images[uri] = {k: row[k] for k in ('name', 'uri', 'repository', 'digest')}
            paths.append({'service': service, 'revision': service + '/revisions/' + revision,
                          'revision_request_url': url, 'uri': uri, 'digest': digest,
                          'traffic_percent': route['percent'], 'tags': sorted(route['tags'])})
    _require(len(images) <= MAX_IMAGES, 'selected_image_reader_bound')
    return {'schema': SCHEMA, 'status': 'planned', 'complete': False, 'content_status': 'not_inspected',
            'scope': scope, 'services': selected, 'coverage': 'selected_services_positive_traffic_and_tagged_revisions',
            'container_limit': 'single_container_revisions_only', 'deployment_paths': paths,
            'selected_artifact_images': [u.removeprefix('https://') for u in sorted(images)],
            'image_rows': [deepcopy(images[u]) for u in sorted(images)],
            'reader_contract': 'peaso.collectors.gcp_image_secret_indicators.inspect_image',
            'metadata_requests': service_requests(scope, selected) + requests}
