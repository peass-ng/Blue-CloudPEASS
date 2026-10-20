"""Account for current official GCP sources without executing upstream code.

--fetch resolves HEAD once and downloads only allowed GCP source blobs into a
32 MiB cache. Default operation is offline against that pinned cache. Reports
separate lineage/catalog presence from semantic equivalence, which is never
inferred. No cloud APIs, upstream code execution, clones, or runtime mutations.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from peaso_review_catalog import blocks, prowler_rows, turbot_rows

REPOS = ('prowler-cloud/prowler', 'turbot/steampipe-mod-gcp-compliance', 'turbot/steampipe-mod-gcp-perimeter')
CACHE = Path('/tmp/peasso-gcp-review-20261019')
LIMIT = 32 * 1024 * 1024
WORKBENCH_IDS = {
    'prowler.gcp.vertexai_workbench_instance_public_ip_disabled': 'gcp.review.workbench.public_ip_disabled',
    'prowler.gcp.vertexai_workbench_instance_root_access_disabled': 'gcp.review.workbench.root_access_disabled',
}



def digest(data):
    return hashlib.sha256(data).hexdigest()


def blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def selected(repo, path):
    if repo != REPOS[0]:
        return path.endswith(('.pp', '.sql'))
    return ((path.startswith('prowler/compliance/gcp/') and path.endswith('.json')) or
            (path.startswith('prowler/providers/gcp/services/') and
             (path.endswith('.metadata.json') or (path.endswith('.py') and path.rsplit('/', 1)[-1] == path.split('/')[-2] + '.py'))))


def cache_bytes(cache):
    # Other dispatched reviewers share the parent /tmp directory. Bound this
    # downloaded source corpus and its accounting files, not their scratch data.
    roots = [cache / repo.split('/')[-1] for repo in REPOS]
    files = [p for root in roots for p in root.rglob('*') if p.is_file()]
    files += [cache / name for name in ('sources.json', 'baseline-prowler-metadata-tree.json', 'source-proposals/checks.json', 'source-proposals/workbench-manifest-rows.json') if (cache / name).is_file()]
    return sum(p.stat().st_size for p in files)


class Fetcher:
    def __init__(self, cache):
        self.cache = cache
        self.lock = threading.Lock()
        self.used = cache_bytes(cache)

    def get(self, url):
        for attempt in range(4):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'peaso-gcp-source-audit', 'Accept': 'application/vnd.github+json'})
                with urllib.request.urlopen(req, timeout=40) as response:
                    data = response.read(LIMIT + 1)
                if len(data) > LIMIT:
                    raise ValueError('response exceeds source cache budget')
                return data
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(1 + attempt)

    def write(self, path, data):
        with self.lock:
            previous = path.stat().st_size if path.exists() else 0
            if self.used - previous + len(data) > LIMIT:
                raise ValueError('32 MiB cache budget exceeded')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.used += len(data) - previous

    def api(self, repo, tail):
        return json.loads(self.get('https://api.github.com/repos/' + repo + '/' + tail))

    def fetch(self):
        sources = []
        for repo in REPOS:
            commit = self.api(repo, 'commits/HEAD')
            revision = commit['sha']
            tree_sha = commit['commit']['tree']['sha']
            if repo == REPOS[0]:
                entries = []
                for prefix in ('prowler/providers/gcp/services', 'prowler/compliance/gcp'):
                    current = tree_sha
                    for part in prefix.split('/'):
                        tree = self.api(repo, 'git/trees/' + current)
                        current = next(x['sha'] for x in tree['tree'] if x['path'] == part)
                    tree = self.api(repo, 'git/trees/' + current + '?recursive=1')
                    if tree.get('truncated'):
                        raise ValueError('truncated tree')
                    entries.extend({**x, 'path': prefix + '/' + x['path']} for x in tree['tree'])
            else:
                tree = self.api(repo, 'git/trees/' + tree_sha + '?recursive=1')
                if tree.get('truncated'):
                    raise ValueError('truncated tree')
                entries = tree['tree']
            entries = sorted((x for x in entries if x['type'] == 'blob' and selected(repo, x['path'])), key=lambda x: x['path'])
            directory = self.cache / repo.split('/')[-1]
            def download(entry):
                path = directory / entry['path']
                data = path.read_bytes() if path.exists() else b''
                if blob_sha(data) != entry['sha']:
                    data = self.get('https://raw.githubusercontent.com/' + repo + '/' + revision + '/' + entry['path'])
                    if blob_sha(data) != entry['sha']:
                        raise ValueError('Git blob mismatch: ' + entry['path'])
                    self.write(path, data)
                return {**entry, 'sha256': digest(data)}
            with ThreadPoolExecutor(max_workers=12) as pool:
                inventory = list(pool.map(download, entries))
            expected_paths = {x['path'] for x in inventory}
            for stale in directory.rglob('*'):
                if stale.is_file() and selected(repo, str(stale.relative_to(directory))) and str(stale.relative_to(directory)) not in expected_paths:
                    with self.lock:
                        self.used -= stale.stat().st_size
                        stale.unlink()
            source = {'repository': repo, 'revision': revision, 'tree_sha': tree_sha, 'license': 'Apache-2.0',
                      'resolved_at': datetime.now(timezone.utc).isoformat(), 'files': inventory}
            source['corpus_sha256'] = digest(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode())
            sources.append(source)
            print(repo, revision, len(inventory), 'verified blobs', flush=True)
        self.write(self.cache / 'sources.json', (json.dumps(sources, indent=2) + '\n').encode())
        baseline = json.loads((ROOT / 'peaso/rulepacks/upstream_manifest.json').read_text())
        revisions = Counter(r['revision'] for r in baseline['checks'] if r['provider'] == 'gcp' and r['repository'] == REPOS[0])
        revision = revisions.most_common(1)[0][0]
        commit = self.api(REPOS[0], 'commits/' + revision)
        current = commit['commit']['tree']['sha']
        walk = []
        for part in 'prowler/providers/gcp/services'.split('/'):
            tree = self.api(REPOS[0], 'git/trees/' + current)
            walk.append({'tree_sha': current, 'selected_component': part})
            current = next(x['sha'] for x in tree['tree'] if x['path'] == part)
        tree = self.api(REPOS[0], 'git/trees/' + current + '?recursive=1')
        if tree.get('truncated'):
            raise ValueError('truncated baseline metadata tree')
        files = [{**x, 'path': 'prowler/providers/gcp/services/' + x['path']} for x in tree['tree']
                 if x['type'] == 'blob' and x['path'].endswith('.metadata.json')]
        self.write(self.cache / 'baseline-prowler-metadata-tree.json', (json.dumps({
            'repository': REPOS[0], 'revision': revision, 'tree_sha': current, 'walk': walk, 'files': files}, indent=2) + '\n').encode())


def verify(cache):
    sources = json.loads((cache / 'sources.json').read_text())
    if {s['repository'] for s in sources} != set(REPOS):
        raise ValueError('unexpected repository inventory')
    for source in sources:
        if not re.fullmatch('[0-9a-f]{40}', source['revision']):
            raise ValueError('unpinned revision')
        files = source['files']
        directory = cache / source['repository'].split('/')[-1]
        actual = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file() and selected(source['repository'], str(p.relative_to(directory)))}
        if actual != {x['path'] for x in files}:
            raise ValueError('cached source tree differs from pinned inventory; refresh required')
        if digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()) != source['corpus_sha256']:
            raise ValueError('inventory fingerprint mismatch')
        for entry in files:
            path = Path(entry['path'])
            if path.is_absolute() or '..' in path.parts or not selected(source['repository'], str(path)):
                raise ValueError('disallowed source path')
            data = (cache / source['repository'].split('/')[-1] / path).read_bytes()
            if blob_sha(data) != entry['sha'] or digest(data) != entry['sha256']:
                raise ValueError('source integrity mismatch: ' + str(path))
    if cache_bytes(cache) > LIMIT:
        raise ValueError('cache exceeds 32 MiB')
    return sources


def enumerate_sources(cache, sources):
    result = []
    for source in sources:
        directory = cache / source['repository'].split('/')[-1]
        inventory = {x['path']: x for x in source['files']}
        if source['repository'] != REPOS[0]:
            rows = turbot_rows(directory, source)
            local_sql = {}
            for path in sorted(directory.rglob('*.pp')):
                for match in re.finditer(r'^\s*(\w+)\s*=\s*<<-?(\w+)\s*\n(.*?)^\s*\2\s*$', path.read_text(), re.M | re.S):
                    local_sql[match[1]] = (match[3], str(path.relative_to(directory)))
            # The shared helper handles .pp queries but not query.sql = file(...).
            # Resolve external SQL explicitly so drift cannot hide behind a filename.
            definitions = {name: (body, path, line) for path in sorted(directory.rglob('*.pp'))
                           for kind, name, body, line in blocks(path.read_text()) if kind == 'query'}
            for row in rows:
                refs = row['upstream_evaluator']['query_ids']
                texts, paths = [], []
                for ref in refs:
                    if ref not in definitions:
                        raise ValueError('unresolved query reference: ' + ref)
                    body, path, line = definitions[ref]
                    paths.append(str(path.relative_to(directory)))
                    external = re.findall(r'file\(\s*"([^\"]+\.sql)"\s*\)', body)
                    if external:
                        for filename in external:
                            candidates = [directory / filename, path.parent / filename]
                            target = next((p for p in candidates if p.is_file()), None)
                            if target is None:
                                raise ValueError('unresolved external SQL: ' + filename)
                            texts.append(target.read_text())
                            paths.append(str(target.relative_to(directory)))
                    else:
                        texts.append(body)
                row['_evaluator_text'] = '\n'.join(texts) if texts else next(body for kind, name, body, line in blocks((directory / row['source'].split(source['revision'] + '/')[1].split('#')[0]).read_text()) if kind == 'control' and name == row['upstream_id'])
                row['_legacy_evaluator_text'] = row['_evaluator_text']
                # Bind shared local SQL as well as the control wrapper. The legacy
                # helper hashes only the wrapper for inline replace(local.sql,...).
                todo = list(re.findall(r'local\.(\w+)', row['_evaluator_text']))
                seen = set()
                while todo:
                    name = todo.pop()
                    if name in seen or name not in local_sql:
                        continue
                    seen.add(name)
                    text, filename = local_sql[name]
                    row['_evaluator_text'] += '\n-- local.' + name + '\n' + text
                    paths.append(filename)
                    todo.extend(re.findall(r'local\.(\w+)', text))
                row['_evaluator_paths'] = sorted(set(paths))
                row['upstream_evaluator']['resolved_sha256'] = digest(row['_evaluator_text'].encode())
                row['_source_paths'] = [row['source'].split(source['revision'] + '/')[1].split('#')[0]]
            # Include query definitions independently; controls remain the comparison unit.
            source['query_inventory'] = [{'id': name, 'path': str(path.relative_to(directory)), 'line': line}
                                         for name, (body, path, line) in sorted(definitions.items())]
        else:
            compliance = defaultdict(list)
            for path in sorted((directory / 'prowler/compliance/gcp').glob('*.json')):
                data = json.loads(path.read_text())
                for req in data.get('Requirements', []):
                    for cid in req.get('Checks', []):
                        compliance[cid].append({'framework_id': path.stem, 'control_id': str(req['Id']), 'source': str(path.relative_to(directory))})
            rows = []
            for filename in inventory:
                if not filename.endswith('.metadata.json'):
                    continue
                data = json.loads((directory / filename).read_text())
                cid = data['CheckID']
                codepath = str(Path(filename).with_name(cid + '.py'))
                code = (directory / codepath).read_text()
                rows.append({'check_id': 'prowler.gcp.' + cid, 'upstream_id': cid, 'title': data['CheckTitle'],
                             'repository': source['repository'], 'revision': source['revision'],
                             'source': 'https://github.com/' + source['repository'] + '/blob/' + source['revision'] + '/' + filename,
                             'frameworks': compliance.pop(cid, []), '_evaluator_text': code, '_source_paths': [filename], '_evaluator_paths': [codepath],
                             'upstream_evaluator': {'sha256': digest(code.encode()), 'resolved_sha256': digest(code.encode())},
                             'official_docs': [data.get('Remediation', {}).get('Recommendation', {}).get('Url', '')]})
            for cid, frameworks in sorted(compliance.items()):
                rows.append({'check_id': 'prowler.gcp.' + cid, 'upstream_id': cid, 'title': 'Unresolved compliance reference',
                             'repository': source['repository'], 'revision': source['revision'], 'frameworks': frameworks,
                             'source': 'https://github.com/' + source['repository'] + '/tree/' + source['revision'] + '/prowler/compliance/gcp',
                             '_evaluator_text': '', '_evaluator_paths': [], '_source_paths': sorted({x['source'] for x in frameworks}),
                             'upstream_evaluator': {'sha256': None, 'resolved_sha256': None}})
        for row in rows:
            row['source_blobs'] = [{**inventory[p]} for p in sorted(set(row['_source_paths'] + row['_evaluator_paths']))]
        result.extend(rows)
    ids = [r['check_id'] for r in result]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate upstream IDs')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=CACHE)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--workbench-payload', action='store_true', help='Write the two-row root admission payload under the cache; never mutate shared catalogs')
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/gcp-review')
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    if args.fetch:
        Fetcher(args.cache).fetch()
    sources = verify(args.cache)
    rows = enumerate_sources(args.cache, sources)
    print('enumerated', len(rows), dict(Counter(r['repository'] for r in rows)))
    if args.workbench_payload:
        write_workbench_payload(args.cache, sources, rows)
    report(args.cache, args.output, sources, rows)


def admission_state(row, mapped, catalog):
    native_id = WORKBENCH_IDS.get(row['check_id'])
    if native_id is None:
        return None
    manifest_mapped = native_id in mapped
    catalog_active = native_id in catalog
    requirements = deepcopy(catalog.get(native_id, {}).get('requirement_controls', []))
    return {'native_id': native_id, 'manifest_mapping_present': manifest_mapped,
            'active_catalog_present': catalog_active,
            'disposition': ('mapped-active' if manifest_mapped and catalog_active else
                            'awaiting-catalog-regeneration' if manifest_mapped else
                            'awaiting-manifest-mapping' if catalog_active else
                            'awaiting-manifest-and-catalog'),
            'requirements': requirements, 'requirement_mapping_assurance': ('reviewed_partial' if requirements and all(r.get('decision') == 'PARTIAL' for r in requirements) else 'catalog_requirement_associations' if requirements else 'thematic_only')}


def write_workbench_payload(cache, sources, rows):
    """Generate a root-owned merge payload; provider overrides preserve global pins."""
    from peaso.checks import CHECKS
    native = {check.id: check for check in CHECKS}
    source = next(s for s in sources if s['repository'] == REPOS[0])
    expected_revision = '76cde39b08092b5d759e25a6cebde0da7e91e5fe'
    if source['revision'] != expected_revision:
        raise ValueError('Workbench admission requires the reviewed Prowler revision')
    current = {row['check_id']: row for row in rows}
    parsed = {row['check_id']: row for row in prowler_rows(cache / 'prowler', source)}
    checks = []
    for upstream_id, native_id in WORKBENCH_IDS.items():
        if native_id not in native or native[native_id].provider != 'gcp':
            raise ValueError('Workbench native is not registered: ' + native_id)
        row = deepcopy(parsed[upstream_id])
        row.update(disposition='ported', native_checks=[native_id], runtime_provider_supported=True,
                   reason=('Reviewed native Workbench v2 declaration against the pinned Prowler evaluator: '
                           'DELETED instances are not applicable; native scope and state validation reject malformed subjects, '
                           'and provider defaults are used only with proven full-response provenance. '
                           'No owner sensitivity comparator is required and no effective network reachability is inferred.'),
                   official_docs=['https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances#GceSetup',
                                  'https://cloud.google.com/vertex-ai/docs/workbench/instances/manage-metadata'],
                   expected_cost={'cloud_calls_at_evaluation': 0, 'snapshot': 'linear in applicable resources'},
                   native_evaluators=[{'check_id': native_id, 'version': '1.0.0', 'language': 'python',
                                       'entrypoint': 'peaso.checks:evaluate_check', 'dependencies': list(native[native_id].dependencies)}],
                   source_review={'source_path': row['upstream_evaluator']['source_path'],
                                  'source_sha256': row['upstream_evaluator']['sha256'],
                                  'source_blobs': current[upstream_id]['source_blobs'],
                                  'compliance_mapping_blobs': [entry for entry in source['files'] if entry['path'] in {mapping['source'] for mapping in row['frameworks']}],
                                  'native_unit': 'Workbench instance in the selected project',
                                  'native_source': 'peaso/checks/gcp_workbench_review_20261019.py',
                                  'native_source_sha256': digest((ROOT / 'peaso/checks/gcp_workbench_review_20261019.py').read_bytes()),
                                  'assurance': 'reviewed declared setting; thematic only, no compliance requirement assertion'})
        row['framework_mapping_assurance'] = 'upstream_lineage_only; native requirements remain thematic_only'
        row['requirements'] = []
        checks.append(row)
    manifest_path = ROOT / 'peaso/rulepacks/upstream_manifest.json'
    manifest = json.loads(manifest_path.read_text())
    before = next(s for s in manifest['sources'] if s['repository'] == REPOS[0])
    after = deepcopy(before)
    after.setdefault('provider_revisions', {})['gcp'] = expected_revision
    after.setdefault('provider_references', {})['gcp'] = {
        'revision': expected_revision, 'source': 'https://github.com/' + REPOS[0] + '/tree/' + expected_revision,
        'git_tree_sha': source['tree_sha'], 'reference_tree_sha256': source['corpus_sha256'],
        'fingerprint_method': 'sha256(canonical JSON selected file inventory with Git blob SHA, SHA256, path, size and type)',
        'scope': 'Only GCP metadata, evaluator Python and compliance JSON; global source and other-provider pins remain unchanged.',
        'source_files': len(source['files']),
        'metadata_files': sum(x['path'].endswith('.metadata.json') for x in source['files']),
        'compliance_files': sum(x['path'].startswith('prowler/compliance/gcp/') for x in source['files'])}
    canonical_path = ROOT / 'peaso/rulepacks/compliance_requirements.json'
    canonical_pack = json.loads(canonical_path.read_text())
    canonical = {(framework['id'], requirement['requirement_id']): requirement
                 for framework in canonical_pack['frameworks'] for requirement in framework['requirements']}
    requirement_candidates = []
    for row in checks:
        for mapping in row['frameworks']:
            upstream_file = cache / 'prowler' / mapping['source']
            upstream_requirement = next(req for req in json.loads(upstream_file.read_text())['Requirements'] if str(req['Id']) == mapping['control_id'])
            existing = canonical.get((mapping['framework_id'], mapping['control_id']))
            if existing is None:
                raise ValueError('Upstream numbered requirement absent from canonical pack: ' + mapping['control_id'])
            requirement_candidates.append({
                'framework_id': mapping['framework_id'], 'requirement_id': mapping['control_id'],
                'upstream_check_id': row['check_id'], 'native_check_id': row['native_checks'][0],
                'upstream_source': 'https://github.com/' + REPOS[0] + '/blob/' + expected_revision + '/' + mapping['source'],
                'upstream_requirement': upstream_requirement, 'canonical_requirement_exists': True,
                'canonical_requirement_snapshot': existing, 'recommended_review_decision': 'PARTIAL',
                'review_boundary': ('The native proves disablePublicIp configuration on current Workbench v2 instances only; '
                                    'it does not establish effective internet reachability, CDE applicability, older notebook coverage, '
                                    'PAN protection, audit-log integrity or complete multi-tenant isolation.' if row['native_checks'][0].endswith('public_ip_disabled') else
                                    'The native proves notebook-disable-root configuration on current Workbench v2 instances only; '
                                    'it does not establish access authorization, business need, CDE applicability or older notebook coverage.'),
                'integration_status': 'candidate_for_root_review_only'})
    payload = {'schema_version': '1.0', 'provider': 'gcp', 'repository': REPOS[0],
               'revision': expected_revision, 'checks': checks,
               'source_pin_update': {'target': 'sources entry whose repository is prowler-cloud/prowler',
                                     'manifest_path': str(manifest_path.relative_to(ROOT)),
                                     'baseline_manifest_sha256': digest(manifest_path.read_bytes()),
                                     'source_entry_before': before, 'source_entry_after': after,
                                     'merge_policy': 'Merge only provider_revisions.gcp and provider_references.gcp; preserve every other key from the latest shared source entry.'},
               'numbered_requirement_review': {'canonical_path': str(canonical_path.relative_to(ROOT)), 'canonical_sha256': digest(canonical_path.read_bytes()), 'candidates': requirement_candidates},
               'extension_mapping': {'native_checks': list(WORKBENCH_IDS.values()), 'requirements': [], 'assurance': 'thematic_only'},
               'integration': 'Root merges these two complete rows and GCP provider source overrides, then regenerates native/runtime catalogs; payload alone does not close audit omissions.'}
    target = cache / 'source-proposals/workbench-manifest-rows.json'
    Fetcher(cache).write(target, (json.dumps(payload, indent=2) + '\n').encode())
    print('Wrote Workbench admission payload:', target)
    return payload


def review_omission(row):
    """Individual source evidence plus a bounded assessment of the titled requirement."""
    title = row['title'].lower()
    cid = row['check_id']
    code = row['_evaluator_text']
    result = {'requirement': row['title'], 'source_evidence': row['source'],
              'evaluator_sha256': row['upstream_evaluator']['resolved_sha256']}
    def decision(kind, reason, docs=(), related=(), proposal=None):
        result.update(classification=kind, assessment=reason, official_documentation=list(docs), related_native_ids=list(related))
        if proposal:
            result['proposal'] = proposal
        return result
    if 'vertexai_workbench_instance_' in cid:
        public = 'public_ip' in cid
        field = 'gceSetup.disablePublicIp' if public else 'gceSetup.metadata.notebook-disable-root'
        return decision('useful_automatable_gap',
            'Non-DELETED Workbench instances are tested without any owner sensitivity policy. '
            + ('The public_ip_disabled boolean drives PASS/FAIL; it describes a configuration declaration, not proven internet reachability.' if public else
               'The root_access_disabled boolean drives PASS/FAIL; collect the notebook-disable-root metadata declaration with documented omission semantics.')
            + ' Existing policy-dependent Workbench checks are archived and cannot establish equivalence.',
            ['https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances#GceSetup',
             'https://docs.cloud.google.com/gemini-enterprise-agent-platform/notebooks/workbench/instances/manage-metadata'],
            ['gcp_workbench_no_public_ip' if public else 'gcp_workbench_root_disabled'],
            {'group': 'network' if public else 'hardening', 'kind': 'workbench_instance', 'fields': ['name', 'state', field],
             'predicate': 'Skip DELETED; PASS only for the documented disabled setting; malformed or unread representations remain UNKNOWN.',
             'evidence_sentences': [
                 'Workbench instance {name} permits a public IP because disablePublicIp is false.' if public else
                 'Workbench instance {name} permits notebook root access because notebook-disable-root is not enabled.',
                 'The saved configuration was read successfully; this finding describes the instance setting.']})
    if "'info' status" in code and 'Manual verification required.' in code:
        result['upstream_automation'] = 'Constant INFO over gcp_project; no security predicate.'
        if 'secrets are not stored' in title:
            return decision('useful_automatable_gap',
                'The wrapper supplies no predicate, but Functions v2 exposes runtime and build environment maps. '
                'At initial review the native scanned credential-like variable names only; benign names can hold secret values. '
                'Add bounded local value scanning with redacted evidence and explicit coverage; do not fetch Secret Manager payloads or infer a clean workload from truncated content.',
                ['https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig'],
                ['gcp.htbp.function.secret_env_from_secret_manager'],
                {'group': 'hardening', 'kind': 'function', 'fields': ['serviceConfig.environmentVariables', 'buildConfig.environmentVariables'],
                 'predicate': 'Run bounded secret detectors on provider-returned literal values; FAIL only positive matches; absent unreadable/truncated maps yield UNKNOWN coverage.',
                 'evidence_sentences': ['Function {name} contains a likely credential in a literal environment variable.',
                                        'The value is redacted; move it to Secret Manager and rotate the exposed credential.']})
        if 'multi-factor' in title:
            return decision('useful_automatable_gap',
                'Directory users exposes enrollment and enforcement independently. At initial review the native implementation read isEnrolledIn2Sv only, '
                'so enrollment does not establish enforced MFA; external identities and incomplete group expansion also remain unresolved.',
                ['https://developers.google.com/workspace/admin/directory/reference/rest/v1/users'],
                ['gcp.identity.non_service_account_mfa'],
                {'group': 'hardening', 'kind': 'workspace_user', 'fields': ['isEnrolledIn2Sv', 'isEnforcedIn2Sv', 'primaryEmail', 'suspended'],
                 'predicate': 'For supported active Cloud IAM human users require both enrollment and enforcement; unsupported IdPs and unreadable membership stay UNKNOWN.',
                 'evidence_sentences': ['User {primaryEmail} is enrolled in two-step verification but enforcement is disabled.',
                                        'Directory returned both settings for this active identity.']})
        if 'security key' in title:
            return decision('manual_or_partial',
                'Security-key-only enforcement is stronger than enrollment or enforced 2SV. Directory boolean fields do not identify the required authentication factor. '
                'Retain the attestation unless an authoritative per-admin security-key policy source is collected; existing MFA and super-admin separation checks do not establish this requirement.',
                ['https://developers.google.com/workspace/admin/directory/reference/rest/v1/users'], ['gcp.identity.non_service_account_mfa', 'gcp.identity.super_admin_separation'])
        if 'api keys are not created' in title:
            return decision('automatable_related_native',
                'API key inventory can establish key absence with complete pagination. The wrapper remains INFO; active key-absence natives are separate implementations, '
                'so this report proposes reviewed requirement association rather than claiming SQL semantic equivalence.',
                ['https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list'],
                ['gcp.claude.project.no_api_keys', 'gcp.ports.project_no_api_key'])
        if 'api keys only exist for active' in title:
            return decision('automatable_related_native',
                'API key restrictions can be joined to enabled service inventory. Active natives already inspect this declaration; the INFO wrapper is not an executable equivalent. '
                'Wildcard service names and unreadable enabled-service inventory need explicit treatment.',
                ['https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys'],
                ['gcp.apikeys.active_service_restrictions', 'gcp_api_keys_active_services_only'])
        if 'app engine' in title and 'https' in title:
            return decision('automatable_related_native',
                'Serving-version handler securityLevel is readable; active App Engine HTTPS check is a related declarative implementation. '
                'SECURE_ALWAYS declaration does not prove all custom-domain routing or runtime TLS behavior.',
                ['https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions'], ['gcp.appengine.version_https_only'])
        if 'mysql database' in title:
            return decision('manual_or_partial',
                'Cloud SQL users.list exposes account names and hosts, but not passwords or an authenticated database administrative-privilege test. '
                'The active mysql_admin_account_posture check covers readable account posture only; never claim that it proves no privileged authentication is possible.',
                ['https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1/users'], ['gcp.sql.mysql_admin_account_posture'])
        for flag, natives in (
            ('log_error_verbosity', ['gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter']),
            ('log_statement', ['gcp.reviewed.sql.postgres_log_statement']),
            ('log_min_messages', ['gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error'])):
            if flag in title:
                return decision('automatable_related_native',
                    'Cloud SQL settings.databaseFlags exposes ' + flag + '. Related active PostgreSQL flag checks exist, but their exact accepted values '
                    'and provider defaults must be compared with this versioned requirement; INFO is not a flag evaluator and logging configuration is not delivered-log evidence.',
                    ['https://cloud.google.com/sql/docs/postgres/flags'], natives)
        if 'access transparency' in title:
            return decision('manual_or_partial',
                'Recent Access Transparency entries can prove an observed signal. The active signal check correctly returns UNKNOWN when no events exist; '
                'provider personnel may not have accessed the project, so an empty log cannot prove that Access Transparency is disabled or enabled.',
                ['https://cloud.google.com/logging/docs/audit/access-transparency-overview'], ['gcp.logging.access_transparency_entries'])
        if 'operating system updates' in title:
            return decision('useful_automatable_gap',
                'OS Config vulnerabilityReports exposes package vulnerabilities and updateTime. Native patch checks are archived because they require an owner grace period; '
                'a separate native check can flag positive outstanding security updates with explicit observed-time evidence, while unreadable or stale assessments stay UNKNOWN.',
                ['https://cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports'], ['gcp.compute.os_patch_compliance'],
                {'group': 'hardening', 'kind': 'instance', 'fields': ['os_vulnerability_report.updateTime', 'os_vulnerability_report.vulnerabilities'],
                 'predicate': 'Report positive outstanding security vulnerabilities from a complete recent native assessment; never equate missing inventory with patched.',
                 'evidence_sentences': ['VM {name} has outstanding security updates in its latest OS Config assessment.',
                                        'The assessment was recorded at {updateTime}.']})
        if 'bigquery' in title and 'classified' in title:
            return decision('manual_or_partial',
                'BigQuery table schemas expose column policy tags and governance annotations, so metadata coverage and bounded content discovery are automatable. '
                'Whether all data is correctly classified needs taxonomy and content semantics; do not treat arbitrary labels as proof. '
                'A separate advisory can enumerate unannotated columns without claiming full classification compliance.',
                ['https://docs.cloud.google.com/bigquery/docs/column-level-security', 'https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/tables'], (),
                {'group': 'hardening', 'kind': 'bigquery_table', 'fields': ['schema.fields[].policyTags', 'schema.fields[].fields'],
                 'predicate': 'Inventory recursively missing column classification annotations; advisory only unless an explicit classification requirement applies.',
                 'evidence_sentences': ['BigQuery table {name} has columns without a classification annotation.',
                                        'This inventories metadata gaps and does not determine the sensitivity of the stored values.']})
        if cid.endswith('.service_versions'):
            return decision('manual_or_partial',
                'App Engine versions and traffic allocations are readable and can identify inactive or old versions. '
                'The upstream title provides no safe numerical version limit; report version inventory or owner-selected lifecycle policy rather than inventing a security PASS threshold.',
                ['https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions'])
        raise ValueError('unreviewed manual wrapper: ' + cid)
    if cid.endswith('.compute_instance_with_custom_metadata'):
        return decision('unsound_security_predicate',
            'The query tests metadata object non-null, not metadata.items, and skips gke-* names in the status branch. '
            'Object presence does not establish a security setting or secret absence; retain the rejection of this predicate, but startup-script/metadata secret content scanning remains independently useful.',
            ['https://cloud.google.com/compute/docs/reference/rest/v1/instances'])
    if cid.endswith('.compute_target_https_proxy_quic_protocol_enabled'):
        return decision('non_security_preference',
            'The query alarms unless quic_override is ENABLE. The API exposes NONE, ENABLE and DISABLE as supported transport choices; '
            'this predicate supplies no TLS-policy or authentication weakness. A minimum TLS policy check is a separate security predicate.',
            ['https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies'])
    if cid.endswith('.kubernetes_cluster_with_less_than_three_node_auto_upgrade_enabled'):
        return decision('unsound_security_predicate',
            'The SQL alarms when autoUpgrade=true and cluster current_node_count<3, contradicting its title, and uses cluster-wide size per node pool. '
            'Do not reproduce this inverted availability heuristic; node auto-upgrade configuration is independently automatable.',
            ['https://cloud.google.com/kubernetes-engine/docs/concepts/node-auto-upgrades'])
    if cid.endswith(('.kubernetes_cluster_with_resource_labels', '.sql_instance_with_labels')):
        return decision('governance_without_security_predicate',
            'The query checks only whether the labels object is null, so an empty object or arbitrary label passes. '
            'No security classification key or enforced authorization rule is identified; labels presence cannot prove secure configuration.',
            ['https://cloud.google.com/resource-manager/docs/creating-managing-labels'])
    if cid.endswith('.compute_public_address_shodan'):
        return decision('external_observation',
            'The evaluator constructs shodan.Shodan(shodan_api_key) and calls api.host(address.ip) for EXTERNAL addresses. '
            'This useful third-party observation needs external credentials and internet-service data; native external-IP/firewall facts cannot prove Shodan indexing parity. '
            'Keep a separately enabled enrichment integration outside provider-read-only coverage rather than mark it semantically covered.',
            ['https://github.com/prowler-cloud/prowler/blob/' + row['revision'] + '/' + row['_evaluator_paths'][0]])
    raise ValueError('omission has no individual review: ' + cid)


def normalized_frameworks(row):
    return sorted((f['framework_id'], f['control_id']) for f in row.get('frameworks', []))


def reconcile_native_successor(row, review, catalog):
    """Retain the initial gap and separately bind its accepted narrower successor."""
    title = row['title'].lower()
    if 'secrets are not stored' in title:
        cid = 'gcp.review.function.literal_environment_secret_indicators'
        source = 'peaso/checks/gcp_function_secret_review_20261019.py'
        receipt = 'docs/gcp-review/function-secret-review.json'
        limits = ('Explicitly selected runtime/build literal environment values only; source archives, '
                  'runtime memory and complete Secret Manager adoption are separate claims. '
                  'The original constant INFO wrapper remains rejected and numbered CIS links remain PARTIAL.')
    elif 'latest operating system updates' in title:
        cid = 'gcp.compute.os_config_fixable_vulnerabilities'
        source = 'peaso/checks/gcp_os_security_update_review_20261019.py'
        receipt = 'docs/gcp-review/os-security-update-review.json'
        limits = ('Native VM/project/report identity and timestamps bind fixable known-vulnerability findings '
                  'at assessment time. Current patch installation, freshness, package ages, all operating '
                  'systems and latest-update requirement completion are not inferred; formal links remain PARTIAL.')
    elif 'multi-factor' in title:
        cid = 'gcp.identity.non_service_account_mfa'
        source = 'peaso/checks/batch_remaining_gcp.py'
        receipt = 'docs/gcp-review/identity-data-review.json'
        limits = ('Both native Directory enrollment and enforcement settings are required for directly '
                  'observed, customer-bound IAM human users. Unsupported external identities, indirect '
                  'membership and unreadable customer bindings remain UNKNOWN; no full requirement equivalence.')
    else:
        return
    if cid not in catalog:
        return
    review['current_native_reconciliation'] = {
        'status': 'implemented_bounded_successor', 'native_id': cid,
        'source': source, 'source_sha256': digest((ROOT / source).read_bytes()),
        'receipt': receipt, 'receipt_sha256': digest((ROOT / receipt).read_bytes()),
        'limits': limits, 'full_upstream_equivalence': False, 'live_verified': False}


def report(cache, output, sources, rows):
    paths = {'manifest': ROOT / 'peaso/rulepacks/upstream_manifest.json',
             'active_native_catalog': ROOT / 'peaso/rulepacks/native_catalog.json',
             'archived_native_scope': ROOT / 'peaso/checks/native_only.json'}
    baseline = {r['check_id']: r for r in json.loads(paths['manifest'].read_text())['checks'] if r['provider'] == 'gcp'}
    catalog = {c['id']: c for c in json.loads(paths['active_native_catalog'].read_text())['checks'] if c['provider'] == 'gcp'}
    excluded = json.loads(paths['archived_native_scope'].read_text())['checks']
    baseline_metadata_path = cache / 'baseline-prowler-metadata-tree.json'
    metadata_baseline = json.loads(baseline_metadata_path.read_text())
    baseline_metadata = {x['path']: x['sha'] for x in metadata_baseline['files']}
    findings = []
    proposals = []
    for row in sorted(rows, key=lambda r: r['check_id']):
        old = baseline.get(row['check_id'])
        mapped = old.get('native_checks', []) if old else []
        active = sorted(set(mapped) & catalog.keys())
        archived = sorted(set(mapped) & excluded.keys())
        unresolved = sorted(set(mapped) - catalog.keys() - excluded.keys())
        if old is None:
            status = 'missing'
        elif active:
            status = 'mapped-active'
        elif mapped and archived and not unresolved:
            status = 'mapped-only-archived'
        elif old['disposition'] == 'rejected':
            status = 'rejected'
        else:
            status = 'missing'
        changes = []
        if old:
            if row['repository'] == REPOS[0] and old['revision'] == metadata_baseline['revision']:
                for entry in row['source_blobs']:
                    if entry['path'].endswith('.metadata.json') and entry['sha'] != baseline_metadata.get(entry['path']):
                        changes.append('metadata_blob')
            if old['upstream_evaluator'].get('sha256') != row['upstream_evaluator'].get('sha256'):
                changes.append('evaluator')
            if normalized_frameworks(old) != normalized_frameworks(row):
                changes.append('framework_control_mappings')
            if old.get('title') != row['title']:
                changes.append('title')
            if old['upstream_evaluator'].get('query_ids', []) != row['upstream_evaluator'].get('query_ids', []):
                changes.append('query_references')
            old_path = old['source'].split('/' + old['revision'] + '/')[-1].split('#')[0]
            new_path = row['source'].split('/' + row['revision'] + '/')[-1].split('#')[0]
            if old_path != new_path:
                changes.append('source_path')
        item = {'check_id': row['check_id'], 'title': row['title'], 'repository': row['repository'], 'revision': row['revision'],
                'status': status, 'source': row['source'], 'source_blobs': row['source_blobs'],
                'upstream_evaluator': row['upstream_evaluator'], 'baseline_revision': old['revision'] if old else None,
                'baseline_evaluator_sha256': old['upstream_evaluator'].get('sha256') if old else None,
                'baseline_disposition': old['disposition'] if old else None, 'native_checks': mapped,
                'active_native_checks': active, 'archived_native_checks': archived, 'unresolved_native_checks': unresolved,
                'changes': changes, 'semantic_equivalence': 'not_inferred_from_lineage_or_catalog_presence',
                'framework_control_mappings': normalized_frameworks(row)}
        admission = admission_state(row, mapped, catalog)
        if admission is not None:
            item['proposal_admission'] = admission
        if status in ('rejected', 'missing'):
            item['review'] = review_omission(row)
        elif status == 'mapped-only-archived':
            corporate = 'iam_corporate_domain_declaration' in mapped[0]
            item['review'] = {
                'classification': 'owner_policy_required', 'requirement': row['title'],
                'assessment': ('The SQL compares user email domains against organization owner directoryCustomerId; the native requires an explicit trusted_domains list. '
                               'Organization association does not identify every legitimate external user. An org-derived comparator is a useful advisory, not an equivalent corporate-identity verdict.' if corporate else
                               'The resolved shared SQL compares each non-project user/group/domain/service-account member against $1-$4 trusted-principal lists; only-project members produce INFO. '
                               'IAM APIs expose bindings but do not establish organizational trust of every identity. Public principal detection is automatable separately; it does not replace the trust-list predicate.'),
                'source_evidence': row['source'],
                'archived_reasons': {cid: excluded[cid] for cid in archived},
                'official_documentation': ['https://cloud.google.com/iam/docs/policies']}
        if changes:
            item.setdefault('review', {})['changed_source_review'] = 'Source drift requires fresh predicate/mapping review; no equivalence claim is carried forward automatically.'
        if 'review' in item:
            reconcile_native_successor(row, item['review'], catalog)
            # Short, decisive excerpts preserve the audited condition, not a substitute implementation.
            item['review']['decisive_source_lines'] = [line.strip() for line in row['_evaluator_text'].splitlines()
                if re.search(r"'info' status|Manual verification|when |trusted_|\$[1-4]|api.host|public_ip_disabled|root_access_disabled|DELETED", line)][:12]
            related = item['review'].get('related_native_ids', [])
            item['review']['related_native_states'] = {cid: ('active' if cid in catalog else 'archived' if cid in excluded else 'unresolved') for cid in related}
            if item['review'].get('proposal'):
                proposals.append({'upstream_id': row['check_id'], 'source': row['source'], **({'proposal_admission': admission} if admission else {}), **item['review']['proposal']})
        findings.append(item)
    current_ids = {x['check_id'] for x in findings}
    retired = [{'check_id': cid, 'baseline_revision': row['revision'], 'assessment': 'No current upstream definition/reference; retain historical provenance only.'}
               for cid, row in sorted(baseline.items()) if cid not in current_ids]
    for source in sources:
        if source['repository'] == REPOS[0]:
            source['baseline_metadata_tree'] = metadata_baseline
        for query in source.get('query_inventory', []):
            related = [x for x in findings if x['repository'] == source['repository'] and query['id'] in x['upstream_evaluator'].get('query_ids', [])]
            query['qualified_id'] = source['repository'].split('/')[-1].removeprefix('steampipe-mod-') + '.query.' + query['id']
            query['control_ids'] = [x['check_id'] for x in related]
            query['control_status_counts'] = dict(Counter(x['status'] for x in related))
            if not related:
                raise ValueError('unaccounted query: ' + query['qualified_id'])
    summary = {'current_upstream_ids': len(findings), 'baseline_upstream_ids': len(baseline),
               'independent_query_definitions': sum(len(s.get('query_inventory', [])) for s in sources), 'active_native_gcp_checks': len(catalog), 'status_counts': dict(Counter(x['status'] for x in findings)),
               'changed_existing_ids': sum(bool(x['changes']) for x in findings), 'retired_upstream_ids': len(retired),
               'review_classifications': dict(Counter(x['review']['classification'] for x in findings if 'review' in x)),
               'bounded_native_successor_reconciliations': sum('current_native_reconciliation' in x.get('review', {}) for x in findings),
               'unreconciled_initial_useful_gap_source_ids': sum(x.get('review', {}).get('classification') == 'useful_automatable_gap'
                    and 'current_native_reconciliation' not in x.get('review', {})
                    and x.get('proposal_admission', {}).get('disposition') != 'mapped-active' for x in findings),
               'proposal_source_ids': len(proposals), 'distinct_proposal_contracts': len({json.dumps({k: v for k, v in p.items() if k not in ('upstream_id', 'source')}, sort_keys=True) for p in proposals}), 'source_cache_bytes': cache_bytes(cache), 'by_repository': dict(Counter(x['repository'] for x in findings))}
    for filename in ('scripts/audit_gcp_source_parity.py', 'scripts/peaso_review_catalog.py',
                     'peaso/checks/hacktricks_bp_gcp.py', 'peaso/checks/batch_remaining_gcp.py'):
        paths[filename] = ROOT / filename
    data = {'schema_version': '1.0', 'scope': 'Official current GCP source accounting; catalog presence is not semantic parity.',
            'reproduce': 'python scripts/audit_gcp_source_parity.py --cache /tmp/peasso-gcp-review-20261019',
            'refresh': 'python scripts/audit_gcp_source_parity.py --fetch --cache /tmp/peasso-gcp-review-20261019',
            'input_hashes': {key: {'path': str(path.relative_to(ROOT)), 'sha256': digest(path.read_bytes())} for key, path in paths.items()},
            'summary': summary, 'sources': sources,
            'limitations': ['Mapped-active is an explicit historical association to an active native ID, not a semantic equivalence result.',
                            'Prowler metadata blobs are compared with the pinned baseline Git subtree; title/path/query/evaluator/framework mappings are compared against manifest projections. Current source bytes are Git-blob verified.',
                            'Legacy perimeter evaluator hashes cover wrappers. resolved_sha256 additionally binds referenced local SQL; unchanged pinned Steampipe revision binds the old shared SQL bytes.',
                            'Manual INFO wrappers are reviewed by requirement independently; positive content scanning remains a useful automatable extension.',
                            'No upstream code was executed and no cloud service was queried.'],
            'checks': findings, 'retired': retired}
    output.mkdir(parents=True, exist_ok=True)
    (output / 'source-parity.json').write_text(json.dumps(data, indent=2) + '\n')
    proposal_path = cache / 'source-proposals' / 'checks.json'
    Fetcher(cache).write(proposal_path, (json.dumps(proposals, indent=2) + '\n').encode())
    lines = ['# GCP current upstream source accounting', '',
             'Reproduce offline: `python scripts/audit_gcp_source_parity.py`. Refresh pinned HEADs: add `--fetch`.', '',
             'All source blobs are Git SHA-1 and SHA-256 verified; selected cached metadata/evaluators/JSON/PP/SQL stay within 32 MiB. '
             'No upstream execution, clone, cloud call, runtime or canonical mapping change occurred.', '',
             '## Counts', '', '```json', json.dumps(summary, indent=2), '```', '', '## Exact revisions', '']
    for source in sources:
        lines.append('- [' + source['repository'] + '](https://github.com/' + source['repository'] + '/tree/' + source['revision'] + '): `' + source['revision'] + '`, tree `' + source['tree_sha'] + '`, corpus SHA-256 `' + source['corpus_sha256'] + '`; ' + str(len(source['files'])) + ' verified blobs.')
    lines += ['', '## Interpretation', '', *['- ' + x for x in data['limitations']], '',
              'Proposal contracts and 1–2 natural evidence sentences are in `/tmp/peasso-gcp-review-20261019/source-proposals/checks.json`. '
              'They use existing network/hardening groups; coordinator owns runtime and mapping admission.', '',
              '## Workbench root admission', '',
              *['- `' + item['check_id'] + '` → `' + item['proposal_admission']['native_id'] + '`: **' + item['proposal_admission']['disposition'] + '**; requirement assurance: ' + item['proposal_admission']['requirement_mapping_assurance'] + ', without full requirement certification.' for item in findings if 'proposal_admission' in item], '',
              '## Individually inspected omissions and archived mappings', '']
    for item in findings:
        if 'review' not in item:
            continue
        review = item['review']
        lines += ['### ' + item['check_id'], '', '**' + item['status'] + ' / ' + review['classification'] + '** — ' + item['title'], '',
                  review['assessment'], '', '[Exact upstream source](' + item['source'] + ').']
        if review.get('official_documentation'):
            lines[-1] += ' ' + ' '.join('[Official documentation ' + str(i + 1) + '](' + url + ').' for i, url in enumerate(review['official_documentation']))
        if review.get('related_native_states'):
            lines += ['', 'Related native states: ' + ', '.join('`' + cid + '` (' + state + ')' for cid, state in review['related_native_states'].items()) + '.']
        if item.get('proposal_admission'):
            admission = item['proposal_admission']
            lines += ['', 'Root admission: `' + admission['native_id'] + '` — **' + admission['disposition'] + '**; requirement assurance: ' + admission['requirement_mapping_assurance'] + '.']
        if review.get('proposal'):
            lines += ['', 'Proposed evidence: ' + ' '.join(review['proposal']['evidence_sentences'])]
        lines += ['']
    lines += ['## Complete per-ID index', '', '| Upstream ID | Status | Active native IDs | Changes |', '| --- | --- | --- | --- |']
    for item in findings:
        lines.append('| [' + item['check_id'] + '](' + item['source'] + ') | ' + item['status'] + ' | ' + ', '.join(item['active_native_checks']) + ' | ' + ', '.join(item['changes']) + ' |')
    (output / 'source-parity.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
