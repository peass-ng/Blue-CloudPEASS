"""Metadata-only native Docker/SBOM inventory and scoped Cloud Run deployment joins.

The owner supplies workload scope, never image evidence. v1 revision status
provides the resolved image digest. Container contents, environment, commands,
and SBOM document contents are never fetched or retained.
"""
import re
from urllib.parse import unquote


def _error(code):
    from .gcp import ReadError
    return ReadError('unavailable', code)


def _digest_uri(value):
    if not isinstance(value, str):
        raise _error('sbom_image_uri_missing')
    uri = value.removeprefix('https://')
    match = re.fullmatch(r'([a-z0-9-]+)-docker\.pkg\.dev/([a-z0-9-]+)/([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]+)@(sha256:[a-f0-9]{64})', uri)
    if not match or any(p in ('', '.', '..') for p in match.group(4).split('/')):
        raise _error('sbom_image_digest_or_repository_unresolved')
    location, project, repo, image, digest = match.groups()
    return 'https://' + uri, f'projects/{project}/locations/{location}/repositories/{repo}', digest


def _images(collector, scope):
    from .gcp_compliance_wave import complete_parent
    repos = complete_parent(collector, 'artifact_repository', scope)
    seen = set()
    for repo in repos['items']:
        name = repo.get('name')
        if not isinstance(name, str) or not re.fullmatch(re.escape(scope) + r'/locations/[a-z0-9-]+/repositories/[A-Za-z0-9._-]+', name):
            raise _error('sbom_repository_identity_unresolved')
        if repo.get('format') != 'DOCKER':
            raise _error('sbom_repository_format_unsupported')
        def keep(row, name=name):
            uri, actual_repo, digest = _digest_uri(row.get('uri'))
            if (actual_repo != name or not isinstance(row.get('name'), str) or not row['name'].startswith(name + '/dockerImages/')
                    or unquote(row['name'][len(name + '/dockerImages/'):]) != uri.removeprefix('https://').split('/', 3)[3]
                    or uri in seen):
                raise _error('sbom_image_foreign_or_duplicate')
            seen.add(uri)
            return {'name': row['name'], 'repository': name, 'uri': uri, 'digest': digest}
        yield from collector.pages('https://artifactregistry.googleapis.com/v1/' + name + '/dockerImages',
            scope, key='dockerImages', params={'fields': 'dockerImages(name,uri),nextPageToken'}, transform=keep)
    if not repos['items']:
        for rid in repos['source_requests']:
            yield [], rid


def _occurrences(collector, scope):
    def keep(row):
        name, kind, note, resource = (row.get(k) for k in ('name', 'kind', 'noteName', 'resourceUri'))
        if (not isinstance(name, str) or not re.fullmatch(re.escape(scope) + r'/occurrences/[A-Za-z0-9_-]+', name)
                or kind != 'SBOM_REFERENCE' or not isinstance(note, str)
                or not re.fullmatch(r'projects/[A-Za-z0-9._:-]+/notes/[A-Za-z0-9._:-]+', note)):
            raise _error('sbom_occurrence_identity_unresolved')
        uri, _, _ = _digest_uri(resource)
        return {'name': name, 'kind': kind, 'noteName': note, 'resourceUri': uri}
    yield from collector.pages('https://containeranalysis.googleapis.com/v1/' + scope + '/occurrences',
        scope, key='occurrences', params={'filter': 'kind="SBOM_REFERENCE"',
        'fields': 'occurrences(name,kind,noteName,resourceUri),nextPageToken'}, transform=keep)


def _read_run(collector, url, scope, fields):
    params = {'fields': fields}
    with collector.lock:
        if not hasattr(collector.transport, 'run_sbom_metadata_reads'):
            collector.transport.run_sbom_metadata_reads = {}
        collector.transport.run_sbom_metadata_reads[url] = (scope, params)
    return collector.read(url, scope, params=params)


def _deployed(collector, scope):
    from .gcp_compliance_wave import complete_parent
    from peaso.gcp_sbom_policy import normalize
    try:
        policy = normalize(collector.options.get('sw52'), collector.scopes)
    except ValueError:
        raise _error('sbom_owner_workload_scope_unavailable_or_mismatched') from None
    if policy['scope'] != scope:
        raise _error('sbom_owner_workload_scope_unavailable_or_mismatched')
    approved = policy['sbomCloudRunServices']
    repositories = complete_parent(collector, 'artifact_repository', scope)
    repository_index = {row.get('name'): row for row in repositories['items']}
    if len(repository_index) != len(repositories['items']):
        raise _error('sbom_deployed_repository_inventory_ambiguous')
    services = complete_parent(collector, 'cloudrun_service', scope)
    native = {r.get('name'): r for r in services['items']}
    if len(native) != len(services['items']) or not set(approved) <= set(native):
        raise _error('sbom_cloudrun_service_join_incomplete')
    projects = complete_parent(collector, 'project', scope)
    aliases = {scope.split('/')[1]}
    for row in projects['items']:
        if row.get('projectId') == scope.split('/')[1] and re.fullmatch(r'projects/[0-9]+', str(row.get('name'))):
            aliases.add(row['name'].split('/')[1])
    for service in approved:
        region, short = service.split('/')[3], service.rsplit('/', 1)[1]
        base = 'https://' + region + '-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/' + scope.split('/')[1]
        value, rid = _read_run(collector, base + '/services/' + short, scope,
            'metadata(name,namespace,generation),status(observedGeneration,traffic)')
        yield [], rid
        metadata, status = value.get('metadata'), value.get('status')
        if (not isinstance(metadata, dict) or metadata.get('name') != short or metadata.get('namespace') not in aliases
                or not isinstance(status, dict) or not metadata.get('generation')
                or str(status.get('observedGeneration')) != str(metadata['generation'])):
            raise _error('sbom_cloudrun_service_foreign_or_reconciling')
        traffic = status.get('traffic')
        if not isinstance(traffic, list) or not traffic:
            raise _error('sbom_cloudrun_traffic_unresolved')
        revisions = set()
        for target in traffic:
            if (not isinstance(target, dict) or not isinstance(target.get('revisionName'), str)
                    or not re.fullmatch(r'[a-z][a-z0-9-]*', target['revisionName'])
                    or type(target.get('percent', 0)) is not int or not 0 <= target.get('percent', 0) <= 100):
                raise _error('sbom_cloudrun_traffic_target_unresolved')
            if target.get('percent', 0) > 0 or target.get('tag'):
                revisions.add(target['revisionName'])
        if not revisions or sum(t.get('percent', 0) for t in traffic) != 100:
            raise _error('sbom_cloudrun_traffic_incomplete')
        for revision in sorted(revisions):
            value, rid = _read_run(collector, base + '/revisions/' + revision, scope,
                'metadata(name,namespace,labels),spec(containers(image)),status(imageDigest,conditions)')
            yield [], rid
            meta, spec, status = value.get('metadata'), value.get('spec'), value.get('status')
            if (not isinstance(meta, dict) or meta.get('name') != revision or meta.get('namespace') not in aliases
                    or not isinstance(meta.get('labels'), dict) or meta['labels'].get('serving.knative.dev/service') != short
                    or not isinstance(spec, dict) or not isinstance(spec.get('containers'), list) or len(spec['containers']) != 1
                    or not isinstance(status, dict) or not isinstance(status.get('conditions'), list)
                    or [c.get('status') for c in status['conditions'] if isinstance(c, dict) and c.get('type') == 'Ready'] != ['True']):
                raise _error('sbom_cloudrun_revision_unsupported_or_not_ready')
            uri, repo, digest = _digest_uri(status.get('imageDigest'))
            if not repo.startswith(scope + '/'):
                raise _error('sbom_cross_project_image_unresolved')
            # The evaluator iterates inventoried repositories. Emitting an
            # unseen repository would hide that deployment from every check.
            if repo not in repository_index or repository_index[repo].get('format') != 'DOCKER':
                raise _error('sbom_deployed_repository_join_unresolved')
            yield [{'name': service + '/revisions/' + revision, 'repository': repo, 'digest': digest,
                    'source_model': 'cloudrun_v1_resolved_revision', 'uri': uri}], rid


def collect(collector):
    jobs = []
    for scope in collector.scopes:
        if not scope.startswith('projects/'):
            continue
        for kind, api, fetch in (('artifact_image', 'artifactregistry', _images),
                ('sbom_occurrence', 'containeranalysis', _occurrences), ('deployed_image', 'run', _deployed)):
            if kind in collector.needed:
                jobs.append((kind, scope, api, lambda fetch=fetch, scope=scope: fetch(collector, scope)))
    collector.run_jobs(jobs)
    policy = collector.options.get('sw52')
    for (kind, scope), collection in collector.collections.items():
        if kind == 'deployed_image':
            collection['scope_model'] = 'owner_approved_cloudrun_service_subset'
            collection['approved_cloudrun_services'] = policy.get('sbomCloudRunServices', []) if isinstance(policy, dict) else []
