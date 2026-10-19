#!/usr/bin/env python3
"""Bounded, read-only AWS Prowler parity audit; no upstream execution or AWS calls.

--fetch resolves default HEAD using GitHub API, then downloads only AWS check
metadata, compliance JSON and all AWS check evaluators (max 32 MiB).
Offline runs require that pinned cache. Registry presence is NOT equivalence.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import inspect
import json
from pathlib import Path
import sys
import urllib.request

REPO = 'prowler-cloud/prowler'
PREFIX = 'prowler/providers/aws/services/'
CAP = 32 * 1024 * 1024

# Individual source review, not inferred from titles or status literals.
EXCLUSION_REVIEWS = {
    'bedrock_agent_role_least_privilege': ('unjustified_security_gap', 'Automatically joins agent execution role with attached/inline policies, admin/escalation predicates and permissions boundary. Missing IAM inventory yields MANUAL, not an inherently manual control.'),
    'bedrock_agent_role_not_shared_across_agents': ('unjustified_security_gap', 'Automatic account-wide role index includes draft and alias-routed deployed versions. Complete inventory permits PASS; confirmed reuse permits FAIL even when incomplete.'),
    'bedrock_api_key_no_administrative_privileges': ('unjustified_security_gap', 'Filters service-specific credential metadata for Bedrock and evaluates user policy documents for admin/escalation/full-service access; credential secret values are unnecessary.'),
    'kms_key_enclave_attestation_not_enforced': ('unjustified_security_gap', 'Enabled customer-managed enclave-tagged/described key policies: sensitive Allow statements must contain RecipientAttestation conditions. Read-only configuration predicate.'),
    'kms_key_enclave_attestation_bypassable_path': ('unjustified_security_gap', 'Sensitive Allow paths must enforce attestation or be neutralized by a paired Deny. Read-only policy predicate; helper semantics and Deny coverage must be ported.'),
    'kms_key_enclave_attestation_no_deployment_binding': ('unjustified_security_gap', 'Attested sensitive Allows need PCR3/PCR4/PCR8 or restrictive account/org binding paired with attestation. Configuration-only informational hardening check.'),
    'rolesanywhere_profile_restricts_session_permissions': ('unjustified_security_gap', 'Evaluates profile session policy, managed policy ARNs and referenced role policies for unrestricted admin access; malformed/unavailable context remains unknown.'),
    'secretsmanager_has_restrictive_resource_policy': ('unjustified_security_gap', 'Resource-policy statements, PrincipalArn/PrincipalServiceName exceptions, explicit Deny, ArnLike validation, organizations and cross-account principals are automatically evaluated. Does not retrieve SecretString.'),
    'kms_key_enclave_attestation_pcr_mismatch': ('excluded_customer_configuration', 'Needs operator enclave_golden_pcr_values from trusted builds; no provider API can establish which image the customer approves. Automatic comparison is possible when supplied.'),
    'kms_key_enclave_attestation_unknown_image': ('excluded_customer_configuration', 'Needs trusted golden PCR values plus bounded CloudTrail runtime attestation events; approval cannot be inferred from provider configuration.'),
    'kms_key_enclave_debug_attestation_detected': ('unresolved_telemetry_gap', 'Automatic zero-PCR0/1/2 detection over bounded CloudTrail events. Requires event-window coverage and truncation handling; no customer golden image list is needed.'),
    'codebuild_project_uses_allowed_github_organizations': ('excluded_customer_configuration', 'Requires customer codebuild_github_allowed_organizations allowlist and project role trust policies. Provider inventory cannot establish approved organizations.'),
    'codepipeline_project_repo_private': ('excluded_external_probe', 'Performs anonymous HTTP HEAD to GitHub and GitLab; failed requests are treated as private PASS. This probe has unreliable private/inaccessible equivalence and exceeds snapshot evaluation.'),
    'ec2_elastic_ip_shodan': ('excluded_external_service', 'Requires customer Shodan API key and third-party host intelligence. AWS inventory does not establish Shodan presence.'),
    'route53_dangling_ip_subdomain_takeover': ('excluded_unsound_upstream_predicate', 'Both FAIL branches infer takeover from absence in this account: an AWS-range A address absent from EIP/ENI inventory, or a website CNAME bucket absent from owned_bucket_names. Legitimate another-account targets satisfy either branch. Neither branch proves release, global nonexistence or claimability; importing this verdict would create false security findings.'),
    'organizations_delegated_administrators': ('excluded_customer_configuration', 'The evaluator compares observed delegates against customer trusted_accounts, defaulting to an empty list. ListDelegatedAdministrators proves delegation but cannot establish which accounts the organization approves. An empty default cannot replace that trust decision.'),
    's3_bucket_object_public': ('unresolved_security_gap', 'Opt-in object List/GetObjectAcl sampling checks AllUsers and AuthenticatedUsers ACL grants; metadata only, no object payload. A sample PASS cannot establish bucket-wide safety.'),
    's3_bucket_shadow_resource_vulnerability': ('excluded_unsound_upstream_predicate', 'Predictable bucket HEAD success is labeled owned by another account without checking ownership in that branch; owned buckets omitted from inventory can be falsely reported. Bucket existence is insufficient proof of takeover.'),
    'ec2_instance_secrets_user_data': ('excluded_secret_content_scope', 'Scans decoded instance user-data content; requires collecting possible plaintext secrets outside metadata-only scope.'),
    'ec2_launch_template_no_secrets': ('excluded_secret_content_scope', 'Scans decoded launch-template user-data content; requires collecting possible plaintext secrets outside metadata-only scope.'),
}


def read(path):
    return json.loads(Path(path).read_text())


def download(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'peaso-parity-audit'}), timeout=60) as response:
        value = response.read(8 * 1024 * 1024 + 1)
    if len(value) > 8 * 1024 * 1024:
        raise ValueError('individual response exceeds 8 MiB cap')
    return value


def source_rows(manifest):
    return [r for r in manifest['checks'] if r.get('repository') == REPO and r.get('provider') == 'aws']


def fetch(cache, manifest):
    api = 'https://api.github.com/repos/' + REPO
    repo = json.loads(download(api))
    commit = json.loads(download(api + '/commits/' + repo['default_branch']))
    revision = commit['sha']
    tree = json.loads(download(api + '/git/trees/' + commit['commit']['tree']['sha'] + '?recursive=1'))
    if tree.get('truncated'):
        raise ValueError('truncated tree cannot establish complete coverage')
    if tree['sha'] != commit['commit']['tree']['sha']:
        raise ValueError('commit and recursive tree do not describe the same tree')
    old = read(cache / 'revision.json') if (cache / 'revision.json').exists() else None
    if old and old['revision'] != revision:
        raise ValueError('cache pins another revision; use a new empty cache')
    selected = {r['path'].replace('.metadata.json', '.py') for r in tree['tree']
                if r['path'].startswith(PREFIX) and r['path'].endswith('.metadata.json')}
    selected.update({r['upstream_evaluator']['source_path'] for r in source_rows(manifest)
                if r.get('disposition') == 'rejected' or r['upstream_id'] in ('organizations_delegated_administrators', 'accessanalyzer_enabled', 'accessanalyzer_enabled_without_findings')})
    entries = [r for r in tree['tree'] if (r['path'].startswith(PREFIX) and r['path'].endswith('.metadata.json'))
               or (r['path'].startswith('prowler/compliance/aws/') and r['path'].endswith('.json')) or r['path'] in selected]
    if sum(r.get('size', 0) for r in entries) + len(json.dumps(tree)) > CAP:
        raise ValueError('selected source files exceed 32 MiB cap')
    cache.mkdir(parents=True, exist_ok=True)
    (cache / 'revision.json').write_text(json.dumps({'repository': REPO, 'default_branch': repo['default_branch'],
        'revision': revision, 'tree_sha': tree['sha'], 'commit_date': commit['commit']['committer']['date']}))
    (cache / 'tree.json').write_text(json.dumps(tree))
    def one(entry):
        target = cache / entry['path']
        if not target.exists():
            data = download('https://raw.githubusercontent.com/' + REPO + '/' + revision + '/' + entry['path'])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(one, entries))


def verified_bytes(cache, entry):
    relative = Path(entry['path'])
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('unsafe cached source path')
    data = (cache / relative).read_bytes()
    digest = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if digest != entry['sha']:
        raise ValueError('cached file does not match pinned Git tree: ' + entry['path'])
    return data


def compliance_index(documents):
    """Index exact framework filename + requirement ID, including nested requirements."""
    result = defaultdict(set)
    def visit(value, framework):
        if isinstance(value, dict):
            if 'Checks' in value:
                for check in value['Checks']:
                    result[check].add((framework, str(value['Id'])))
            for child in value.values():
                visit(child, framework)
        elif isinstance(value, list):
            for child in value:
                visit(child, framework)
    for framework, document in documents.items():
        visit(document.get('Requirements', []), framework)
    return result


def status_assignments(source):
    tree = ast.parse(source)
    return sorted({node.value.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        and any(isinstance(target, ast.Attribute) and target.attr == 'status' for target in node.targets)})


def runtime_predicates(root):
    sys.path.insert(0, str(root))
    from peaso.engine import _registry
    result = {}
    for check in _registry():
        if check.provider != 'aws':
            continue
        function = inspect.unwrap(check.evaluate)
        path = Path(inspect.getsourcefile(function)).resolve()
        result[check.id] = {'path': str(path.relative_to(root)), 'line': inspect.getsourcelines(function)[1],
            'function': function.__qualname__, 'source_sha256': hashlib.sha256(inspect.getsource(function).encode()).hexdigest(),
            'dependencies': list(check.dependencies), 'resource_kind': check.kind, 'target': check.target}
        result[check.id]['function_contract_sha256'] = hashlib.sha256(json.dumps(result[check.id], sort_keys=True).encode()).hexdigest()
    return result


def audit(root, cache, predicates):
    manifest = read(root / 'peaso/rulepacks/upstream_manifest.json')
    native = read(root / 'peaso/rulepacks/native_catalog.json')
    active = {r['id']: r for r in native['checks']}
    archived = {r['id']: r for r in native.get('archived_checks', [])}
    sources = source_rows(manifest)
    by_id = defaultdict(list)
    for row in sources:
        by_id[row['upstream_id']].append(row)
    tree = read(cache / 'tree.json')
    if tree.get('truncated'):
        raise ValueError('truncated tree cannot establish complete coverage')
    revision = read(cache / 'revision.json')
    if revision.get('tree_sha') and revision['tree_sha'] != tree.get('sha'):
        raise ValueError('revision and recursive tree do not describe the same commit')
    entries = {r['path']: r for r in tree['tree']}
    metadata = {}
    for path, entry in entries.items():
        if path.startswith(PREFIX) and path.endswith('.metadata.json'):
            value = json.loads(verified_bytes(cache, entry))
            upstream_id = value['CheckID']
            if upstream_id in metadata:
                raise ValueError('duplicate upstream metadata ID: ' + upstream_id)
            metadata[upstream_id] = (path, value)
    documents = {Path(path).stem: json.loads(verified_bytes(cache, entry)) for path, entry in entries.items()
        if path.startswith('prowler/compliance/aws/') and path.endswith('.json')}
    refs = compliance_index(documents)
    from peaso.collectors import aws as collector
    collector_capabilities = {}
    for kind in sorted({dependency for value in predicates.values() for dependency in value.get('dependencies', [])}):
        capability = {'inventory_spec': list(collector.SPECS[kind]) if kind in collector.SPECS else None,
                      'custom_fetcher': kind in collector.FETCHERS, 'enricher': kind in collector.ENRICHERS}
        capability['contract_sha256'] = hashlib.sha256(json.dumps(capability, sort_keys=True).encode()).hexdigest()
        collector_capabilities[kind] = capability
    rows = []
    for upstream_id, (path, meta) in sorted(metadata.items()):
        matches = by_id.get(upstream_id, [])
        old = matches[0] if matches else {}
        ids = old.get('native_checks', [])
        supported = [cid for cid in ids if cid in active and cid in predicates]
        old_refs = {(r['framework_id'], str(r['control_id'])) for r in old.get('frameworks', [])}
        current_refs = refs.get(upstream_id, set())
        missing = sorted(current_refs - old_refs)
        stale = sorted(old_refs - current_refs)
        native_refs = {(r.get('framework_id'), str(r.get('requirement_id', r.get('control_id'))))
            for cid in supported for r in active[cid].get('requirement_controls', [])}
        issues = []
        if len(matches) != 1:
            issues.append('missing_manifest_row' if not matches else 'duplicate_manifest_rows')
        if missing or stale:
            issues.append('manifest_compliance_drift')
        if supported and current_refs - native_refs:
            issues.append('native_requirement_mapping_gap')
        evaluator_path = path.replace('.metadata.json', '.py')
        evaluator = entries.get(evaluator_path)
        evidence = {'path': evaluator_path, 'git_blob': evaluator.get('sha') if evaluator else None}
        if (cache / evaluator_path).exists() and evaluator:
            code = verified_bytes(cache, evaluator).decode()
            evidence.update(sha256=hashlib.sha256(code.encode()).hexdigest(), status_assignments=status_assignments(code))
            # Manifest parser fingerprints text after universal-newline decoding.
            normalized = code.replace('\r\n', '\n').replace('\r', '\n')
            evidence['normalized_sha256'] = hashlib.sha256(normalized.encode()).hexdigest()
            evidence['raw_sha256_differs_from_manifest'] = evidence['sha256'] != old.get('upstream_evaluator', {}).get('sha256')
            evidence['changed_since_manifest'] = evidence['normalized_sha256'] != old.get('upstream_evaluator', {}).get('sha256')
            if evidence['changed_since_manifest']:
                issues.append('upstream_evaluator_changed_since_manifest')
        elif evaluator:
            issues.append('upstream_evaluator_not_cached')
        review = None
        if old.get('disposition') == 'rejected':
            review = EXCLUSION_REVIEWS.get(upstream_id)
            states = evidence.get('status_assignments', [])
            reason = old.get('reason', '')
            if review:
                disposition = review[0]
                if disposition.startswith('unresolved') or disposition == 'unjustified_security_gap':
                    issues.append('exclusion_needs_individual_security_justification')
            elif states == ['MANUAL']:
                disposition = 'excluded_manual_verified'
            else:
                disposition = 'unresolved_exclusion'
                issues.append('exclusion_needs_individual_security_justification')
        elif not supported:
            disposition = 'unresolved_no_active_native'
            issues.append('claimed_port_without_active_native')
        else:
            disposition = 'mapped_predicate_equivalence_unverified'
        rows.append({'upstream_id': upstream_id, 'title': meta.get('CheckTitle'), 'severity': meta.get('Severity'),
            'disposition': disposition, 'manifest_disposition': old.get('disposition'),
            'native_checks': ids, 'active_native_checks': supported,
            'native_predicates': {cid: predicates[cid] for cid in supported},
            'archived_native_checks': {cid: native.get('excluded_controls', {}).get(cid) for cid in ids if cid in archived},
            'exclusion_reason': old.get('reason') if old.get('disposition') == 'rejected' else None,
            'individual_exclusion_review': {'decision': review[0], 'evidence': review[1]} if review else None,
            'metadata_git_blob': entries[path]['sha'],
            'upstream_evaluator': evidence, 'compliance_references': [list(pair) for pair in sorted(current_refs)],
            'manifest_compliance_missing': missing, 'manifest_compliance_stale': stale,
            'active_native_requirement_references_missing': sorted(current_refs - native_refs) if supported else [],
            'issues': issues})
    return {'schema_version': 1, 'upstream': read(cache / 'revision.json'),
        'upstream_tree_sha256': hashlib.sha256((cache / 'tree.json').read_bytes()).hexdigest(),
        'compliance_git_blobs': {path: entry['sha'] for path, entry in entries.items() if path.startswith('prowler/compliance/aws/') and path.endswith('.json')},
        'manifest_revision': next(r.get('provider_revisions', {}).get('aws', r['revision']) for r in manifest['sources'] if r['repository'] == REPO),
        'local_input_sha256': {name: hashlib.sha256((root / 'peaso/rulepacks' / name).read_bytes()).hexdigest()
                              for name in ('upstream_manifest.json', 'native_catalog.json')},
        'collector_capabilities': collector_capabilities,
        'collector_source_sha256': {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in sorted((root / 'peaso/collectors').glob('aws*.py'))},
        'cache_path': str(cache.resolve()),
        'scope': 'All current AWS metadata IDs and AWS compliance references; registry/source trace is not semantic equivalence. No upstream code executed.',
        'counts': {'current_upstream_ids': len(rows), 'compliance_files': len(documents),
            'manifest_ids_removed_upstream': len(set(by_id) - set(metadata)),
            'dispositions': dict(Counter(r['disposition'] for r in rows)),
            'issues': dict(Counter(issue for r in rows for issue in r['issues']))},
        'manifest_ids_removed_upstream': sorted(set(by_id) - set(metadata)),
        'dangling_upstream_compliance_check_ids': sorted(set(refs) - set(metadata)), 'checks': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cache', type=Path, default=Path('/tmp/peasso-aws-review-20261019/prowler/head-20261019-140026'))
    parser.add_argument('--output', type=Path, default=Path('docs/aws-review/prowler-parity.json'))
    parser.add_argument('--fetch', action='store_true')
    args = parser.parse_args()
    if args.fetch:
        fetch(args.cache, read(args.root / 'peaso/rulepacks/upstream_manifest.json'))
    report = audit(args.root.resolve(), args.cache, runtime_predicates(args.root.resolve()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['counts'], indent=2))


if __name__ == '__main__':
    main()
