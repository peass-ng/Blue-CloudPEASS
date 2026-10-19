"""Audit current AWS Steampipe source lineage without executing upstream code.

Network refresh uses two GitHub HEAD requests, recursive trees and only bounded
pp/sp/sql blobs. Offline runs verify every cached blob against its Git tree SHA.
Registry presence is evidence of implementation, never proof of SQL equivalence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from peaso_review_catalog import blocks, turbot_rows

CACHE = Path('/tmp/peasso-aws-review-20261019/steampipe')
REPOS = ('compliance', 'perimeter')
MAX_FILES, MAX_BYTES = 800, 8_000_000
PARITY_FIELDS = ('title', 'rationale', 'source', 'revision', 'upstream_evaluator',
                 'frameworks', 'upstream_benchmark_ids')
INSPECTOR_DOC = 'https://docs.aws.amazon.com/managedservices/latest/userguide/inspector.html'
PRINCIPAL_DOC = 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html'
SENSITIVE_IDS = {
    'autoscaling_ec2_launch_configuration_no_sensitive_data',
    'cis_compute_service_v100_2_13', 'cloudformation_stack_output_no_secrets',
    'ec2_instance_user_data_no_secrets', 'lambda_function_variables_no_sensitive_data',
}
SENSITIVE_ALTERNATIVES = {
    'ec2_instance_user_data_no_secrets': ['aws.a.ec2.user_data_source_indicators', 'aws_cis_ec2_userdata_embedded_secrets'],
    'cis_compute_service_v100_2_13': ['aws.a.ec2.user_data_source_indicators', 'aws_cis_ec2_userdata_embedded_secrets'],
    'autoscaling_ec2_launch_configuration_no_sensitive_data': ['aws_autoscaling_userdata_plaintext_aws_key'],
    'lambda_function_variables_no_sensitive_data': ['aws.htbp.lambda.env_var_names_not_credentials'],
    'cloudformation_stack_output_no_secrets': [],
}
SENSITIVE_FINDINGS = {
    'ec2_instance_user_data_no_secrets': 'Transient DescribeInstanceAttribute source-pattern projection exists; the coordinator also repaired the high-confidence UserDataSecretIndicators projection during this review. The source-indicator check is not imported in the baseline runtime; high-confidence detection is useful narrower evidence, not exact substring/shape equivalence. Check current candidate states below.',
    'cis_compute_service_v100_2_13': 'Exact query alias of ec2_instance_user_data_no_secrets; same safe transient projection and registration gap. Generic secret-content collection prohibition is not a substantive exclusion.',
    'autoscaling_ec2_launch_configuration_no_sensitive_data': 'Existing pre-cache redaction safely produces HasAwsKeyPair for an active narrower AWS-key-pair check; source substring/password-shape indicators are not equivalent. Extend the existing projection rather than duplicating raw-content collection.',
    'lambda_function_variables_no_sensitive_data': 'Existing name-only active heuristic is partial; source scans keys and values. GetFunctionConfiguration already returns configuration values, so transient indicator projection before any cache can add useful coverage without GetSecretValue.',
    'cloudformation_stack_output_no_secrets': 'No output-content detector found. DescribeStacks returns OutputKey/OutputValue configuration; a bounded transient boolean projection before caching can inspect patterns without retaining values or invoking GetSecretValue.',
}


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(url):
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'Blue-CloudPEASS-parity-review'})
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.read()
        except Exception:
            if attempt == 3:
                raise
            time.sleep(attempt + 1)


def selected_files(tree):
    if tree.get('truncated'):
        raise ValueError('GitHub tree truncated: cannot claim complete coverage')
    files = [x for x in tree['tree'] if x['type'] == 'blob' and
             Path(x['path']).suffix in ('.pp', '.sp', '.sql')]
    if len(files) > MAX_FILES or sum(x['size'] for x in files) > MAX_BYTES:
        raise ValueError('source fetch exceeds bounded file/byte budget')
    for entry in files:
        if Path(entry['path']).is_absolute() or '..' in Path(entry['path']).parts:
            raise ValueError('unsafe source path')
    return files


def corpus(cache, refresh=False):
    result = []
    for name in REPOS:
        repo = 'turbot/steampipe-mod-aws-' + name
        head_path, tree_path = cache / (name + '-head.json'), cache / (name + '-tree.json')
        cache.mkdir(parents=True, exist_ok=True)
        if refresh:
            head_path.write_bytes(fetch('https://api.github.com/repos/' + repo + '/commits/HEAD'))
            head = read(head_path)
            tree_path.write_bytes(fetch('https://api.github.com/repos/' + repo + '/git/trees/' + head['commit']['tree']['sha'] + '?recursive=1'))
        head, tree = read(head_path), read(tree_path)
        if head['commit']['tree']['sha'] != tree['sha']:
            raise ValueError('HEAD and recursive tree do not describe the same commit')
        files = selected_files(tree)
        directory = cache / ('steampipe-mod-aws-' + name)
        directory.mkdir(parents=True, exist_ok=True)

        def download(entry):
            target = directory / entry['path']
            if not refresh and not target.exists():
                raise ValueError('missing cached source; use --refresh: ' + entry['path'])
            if refresh:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(fetch('https://raw.githubusercontent.com/' + repo + '/' + head['sha'] + '/' + entry['path']))

        with ThreadPoolExecutor(max_workers=12) as executor:
            list(executor.map(download, files))
        for entry in files:
            data = (directory / entry['path']).read_bytes()
            git_sha = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if git_sha != entry['sha'] or len(data) != entry['size']:
                raise ValueError('cached blob differs from pinned Git tree: ' + entry['path'])
        expected = {entry['path'] for entry in files}
        actual = {str(path.relative_to(directory)) for path in directory.rglob('*')
                  if path.is_file() and path.suffix in ('.pp', '.sp', '.sql')}
        if actual != expected:
            raise ValueError('cached corpus has missing or stale source files')
        source = {'repository': repo, 'revision': head['sha'], 'license': 'Apache-2.0'}
        rows = turbot_rows(directory, source)
        definitions = {}
        declarations = []
        for entry in files:
            path = directory / entry['path']
            text = path.read_text()
            declarations.extend(re.findall(r'^control\s+"([^"]+)"\s*\{', text, re.M))
            for kind, identifier, body, line in blocks(text):
                if (kind, identifier) in definitions:
                    raise ValueError('duplicate upstream definition: ' + kind + '.' + identifier)
                definitions[(kind, identifier)] = {'body': body, 'path': entry['path'], 'line': line}
        if set(declarations) != {row['upstream_id'] for row in rows} or len(declarations) != len(rows):
            raise ValueError('declaration enumeration and parsed controls differ')
        result.append((source, rows, definitions, {
            **source, 'head_api': 'https://api.github.com/repos/' + repo + '/commits/HEAD',
            'tree_sha': tree['sha'], 'head_metadata_sha256': digest(head_path),
            'source_file_count': len(files), 'source_bytes': sum(x['size'] for x in files),
            'git_blob_verification': 'all selected blobs match recursive tree',
        }))
    return result


def runtime_reference(check):
    function = inspect.unwrap(check.evaluate)
    path = Path(inspect.getsourcefile(function)).resolve()
    return {'id': check.id, 'file': str(path.relative_to(ROOT)),
            'line': inspect.getsourcelines(function)[1], 'dependencies': check.dependencies,
            'title': check.title, 'file_sha256': digest(path)}


def rejection_verdict(identifier, queries, sql, manual_present):
    """Classify each rejected row using source evidence, with explicit exceptions."""
    if identifier == 'ec2_instance_no_high_level_finding_in_inspector_scan':
        return ('justified_retired_service',
                'Automatic SQL reads Inspector Classic High findings; Classic ended support May 20 2026. '
                'Retain historical lineage and document Inspector2 successor separately; do not claim exact equivalence.')
    if identifier in {'ram_resource_shared_with_trusted_accounts',
                      'ram_resource_shared_with_trusted_organization_units',
                      'ram_resource_shared_with_trusted_organizations'}:
        return ('justified_customer_trust_input',
                'Pinned SQL subtracts the supplied $1 trusted-principal array from RAM recipients and reports info for remaining principals. Inventory establishes sharing, but cannot supply customer trust approval.')
    if identifier == 'cloudwatch_cross_account_sharing':
        return ('justified_manual_interpretation',
                'Pinned SQL reports info for CloudWatch-CrossAccountSharingRole principals, not alarm. Observing that named role cannot decide whether cross-account access is approved; the source does not define a universal unsafe-access predicate.')
    if identifier == 'iam_role_cross_account_write_access_policy':
        return ('justified_invalid_upstream_predicate',
                'SQL tests Principal in attached identity policies; IAM forbids Principal in those policies.')
    if identifier in SENSITIVE_IDS:
        return ('unjustified_blanket_sensitive_boundary', SENSITIVE_FINDINGS[identifier])
    if queries == ['manual_control'] and 'Manual verification required' in sql:
        return (('justified_manual_only' if manual_present else 'missing_manual_lineage'),
                'Source emits constant info for manual verification; no automatic security predicate exists.')
    if 'param "trusted_' in sql and "'info'" in sql:
        return (('justified_customer_trust_input' if manual_present else 'missing_manual_lineage'),
                'Source requires a customer trust list and emits info for an untrusted recipient; inventory alone cannot establish approval.')
    return ('uncertain_rejection_requires_review', 'No source-supported exclusion rule matched; review individually.')


def audit(upstreams, manifest, native, manual, runtime):
    manifest_rows = {row['check_id']: row for row in manifest['checks']}
    active = {row['id']: row for row in native['checks']}
    archived = {row['id']: row for row in native.get('archived_checks', [])}
    manual_rows = {row['id']: row for row in manual['requirements']}
    records = []
    for source, rows, definitions, _metadata in upstreams:
        for upstream in rows:
            identifier = upstream['check_id']
            row = manifest_rows.get(identifier, {})
            definition = definitions[('control', upstream['upstream_id'])]
            queries = upstream['upstream_evaluator']['query_ids']
            sql = '\n'.join(definitions[('query', q)]['body'] for q in queries
                            if ('query', q) in definitions) or definition['body']
            unresolved_queries = [q for q in queries if ('query', q) not in definitions]
            mismatches = [field for field in PARITY_FIELDS if row.get(field) != upstream.get(field)]
            references = row.get('native_checks', [])
            active_refs = [cid for cid in references if cid in active and cid in runtime]
            archived_refs = [cid for cid in references if cid in archived]
            missing_refs = [cid for cid in references if cid not in active and cid not in archived]
            details = []
            if not row:
                verdict = 'absent_upstream_control'
            elif unresolved_queries:
                verdict = 'unresolved_upstream_query'
            elif mismatches:
                verdict = 'stale_manifest_source_or_lineage'
            elif archived_refs or missing_refs or len(active_refs) != len(references):
                verdict = 'stale_automatic_coverage_archived_native'
                details.append('Advertised native reference is not an active catalog and runtime check; '
                               'customer-policy/manual evidence must remain explicit and must not count as automatic coverage.')
            elif row.get('disposition') == 'rejected':
                verdict, reason = rejection_verdict(upstream['upstream_id'], queries,
                                                    sql + '\n' + definition['body'], identifier in manual_rows)
                details.append(reason)
            elif not active_refs:
                verdict = 'missing_active_native_implementation'
            else:
                verdict = ('corrected_native_lineage_semantics_not_reexecuted'
                           if 'defective' in row.get('reason', '') else
                           'current_lineage_active_native_semantics_not_reexecuted')
            backref_missing = [cid for cid in active_refs if identifier not in
                               {s.get('check_id') for s in active[cid].get('sources', [])}]
            manual_entry = manual_rows.get(identifier)
            manual_lineage_matches = None if manual_entry is None else (
                manual_entry.get('frameworks') == upstream['frameworks'] and
                manual_entry.get('revision') == source['revision'] and
                manual_entry.get('source') == upstream['source'])
            query_sources = []
            for q in queries:
                query = definitions.get(('query', q))
                if query:
                    query_sources.append({'id': q, 'source': 'https://github.com/' + source['repository'] +
                                          '/blob/' + source['revision'] + '/' + query['path'] + '#L' + str(query['line'])})
                else:
                    details.append('Unresolved upstream query reference: ' + q)
            records.append({
                'control_id': identifier, 'title': upstream['title'],
                'repository': source['repository'], 'revision': source['revision'],
                'source': upstream['source'], 'query_sources': query_sources,
                'evaluator_sha256': upstream['upstream_evaluator']['sha256'],
                'source_dependencies': upstream['dependencies'],
                'compliance_lineage': upstream['frameworks'],
                'upstream_benchmark_ids': upstream['upstream_benchmark_ids'],
                'manifest_present': bool(row), 'manifest_disposition': row.get('disposition'),
                'manifest_mismatches': mismatches, 'manifest_reason': row.get('reason'),
                'active_native': [runtime_reference(runtime[cid]) for cid in active_refs],
                'archived_native': [{'id': cid, 'exclusion': native.get('excluded_controls', {}).get(cid)} for cid in archived_refs],
                'missing_native_ids': missing_refs, 'native_source_backrefs_missing': backref_missing,
                'useful_native_alternatives': [
                    {'id': cid, 'in_runtime': cid in runtime, 'in_active_catalog': cid in active,
                     'equivalence': 'candidate or narrower evidence; not assumed equivalent',
                     **({'runtime': runtime_reference(runtime[cid])} if cid in runtime else {})}
                    for cid in SENSITIVE_ALTERNATIVES.get(upstream['upstream_id'], [])],
                'manual_requirement_present': manual_entry is not None,
                'manual_lineage_matches': manual_lineage_matches,
                'official_docs': row.get('official_docs', []),
                'validity_verdict': verdict,
                'missing_or_uncertain': details + ([
                    'Runtime registration and exact upstream lineage verified; full native-vs-SQL semantic equivalence '
                    'and collection completeness were not independently re-proved by this static audit.'
                ] if active_refs else []),
            })
    current_ids = {row['control_id'] for row in records}
    stale_ids = sorted(row['check_id'] for row in manifest['checks']
                       if row.get('repository') in {s['repository'] for s, *_ in upstreams}
                       and row['check_id'] not in current_ids)
    return {'schema_version': '1.0', 'reviewed_at': '2026-10-19',
            'scope': 'Every declared current control in both AWS Steampipe repositories; static parity, not cloud validation.',
            'upstream_sources': [metadata for *_rest, metadata in upstreams],
            'local_inputs_sha256': {str(path.relative_to(ROOT)): digest(path) for path in (
                ROOT / 'peaso/rulepacks/upstream_manifest.json', ROOT / 'peaso/rulepacks/native_catalog.json',
                ROOT / 'peaso/rulepacks/manual_catalog.json', ROOT / 'peaso/collectors/aws.py',
                ROOT / 'peaso/collectors/aws_facts_ext.py', ROOT / 'peaso/collectors/aws_launch_configuration_redaction.py')},
            'summary': {'control_count': len(records),
                        'by_verdict': dict(sorted(Counter(row['validity_verdict'] for row in records).items())),
                        'removed_upstream_ids_still_in_manifest': stale_ids},
            'records': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=CACHE)
    parser.add_argument('--refresh', action='store_true', help='Resolve current GitHub API HEADs and refetch bounded source files')
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/aws-review/steampipe-parity.json')
    args = parser.parse_args()
    from peaso.engine import _registry
    result = audit(corpus(args.cache, args.refresh), read(ROOT / 'peaso/rulepacks/upstream_manifest.json'),
                   read(ROOT / 'peaso/rulepacks/native_catalog.json'), read(ROOT / 'peaso/rulepacks/manual_catalog.json'),
                   {check.id: check for check in _registry()})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary'], indent=2))


if __name__ == '__main__':
    main()
