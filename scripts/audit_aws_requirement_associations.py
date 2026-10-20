#!/usr/bin/env python3
"""Offline exact source-topic/ledger reconciliation; never imports compliance edges.

All divergences receive source definitions and canonical decisions. Semantic
uncertainty remains explicit: a reviewed alternative is not equivalence proof.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from scripts.audit_aws_prowler_parity import PREFIX, compliance_index, verified_bytes

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_ledgers(root):
    directory = root / 'docs/compliance-ledgers'
    manifest = read(directory / 'manifest.json')
    result, inputs = {}, {}
    for spec in manifest['slices'].values():
        path = directory / spec['path']
        if not spec['verified'] or sha(path) != spec['sha256']:
            raise ValueError('Unverified ledger: ' + str(path))
        inputs[str(path.relative_to(root))] = spec['sha256']
        for framework in read(path)['frameworks']:
            if framework['provider'] == 'aws':
                for requirement in framework['requirements']:
                    key = (framework['id'], requirement['requirement_id'])
                    if key in result:
                        raise ValueError('Duplicate ledger requirement: ' + str(key))
                    result[key] = dict(requirement, ledger=str(path.relative_to(root)))
    return result, inputs


def definitions(documents):
    result = {}
    def visit(value, framework):
        if isinstance(value, dict):
            if 'Id' in value and 'Checks' in value:
                result[(framework, str(value['Id']))] = {
                    'description': value.get('Description', ''),
                    'source_checks': value['Checks'],
                    'source_path': 'prowler/compliance/aws/' + framework + '.json'}
            for child in value.values():
                visit(child, framework)
        elif isinstance(value, list):
            for child in value:
                visit(child, framework)
    for framework, document in documents.items():
        visit(document.get('Requirements', []), framework)
    return result


def reconcile_edge(source_id, native_ids, key, ledger, compiled, accepted=None):
    """Use explicit ledger decisions, never keywords or source association alone."""
    row = ledger.get(key)
    existing = compiled.get(key, {})
    rejected = sorted(set(native_ids) & set((row or {}).get('removed_checks', [])))
    if row is None:
        disposition = 'unresolved_missing_canonical_requirement'
    elif set(rejected) == set(native_ids) and native_ids:
        disposition = 'explicit_canonical_rejection'
    elif set(native_ids) & set(row.get('native_checks', [])):
        disposition = 'unresolved_compiled_membership_differs_from_ledger'
    elif row['decision'] in ('MANUAL', 'NOT_APPLICABLE'):
        disposition = 'canonical_manual_or_out_of_scope'
    else:
        disposition = 'unresolved_additional_signal_semantics'
    review = additional_signal_review(source_id, key) if disposition.startswith('unresolved') else None
    decision = (accepted or {}).get((source_id, *key))
    if (decision and decision.get('admission_status') == 'accepted_by_root'
            and decision.get('intake') == 'source_topic_only_no_runtime_compliance_link'
            and review and decision.get('decision') == review.get('recommendation')
            and decision.get('reason') == review.get('reason')
            and review['recommendation'] in ('retain_topic_only', 'retain_existing_name_predicate')):
        disposition = 'accepted_no_requirement_membership_change'
        review = dict(review, admission_status='accepted_by_root')
    if review and review['recommendation'] == 'propose_add_partial_signal' and row:
        review['proposed_canonical_change'] = {
            'ledger': row.get('ledger'), 'framework_id': key[0], 'requirement_id': key[1],
            'before': {k: row.get(k) for k in ('decision', 'native_checks', 'reason')},
            'after': {'decision': 'PARTIAL',
                      'native_checks': sorted(set(row.get('native_checks', [])) | set(native_ids)),
                      'reason': row['reason'] + ' Additional bounded native signal: ' + review['reason']},
            'admission_status': 'proposal_requires_root_review'}
    return {'source_id': source_id, 'framework_id': key[0], 'requirement_id': key[1],
            'candidate_native_checks': sorted(native_ids), 'disposition': disposition,
            'explicitly_removed_candidates': rejected,
            'current_runtime_status': existing.get('runtime_status'),
            'proposal': 'preserve_source_topic_association_separately',
            'counts_as_requirement_automation': False,
            'compliance_membership_change_authorized': False,
            'directed_review': review}


def additional_signal_review(source_id, key):
    """Explicit reviewed residuals; suggestions stay separate from ledger admission."""
    fid, rid = key
    if source_id == 'codebuild_project_no_secrets_in_variables':
        if fid == 'pci_4.0_aws':
            return {'recommendation': 'retain_topic_only', 'reason': 'This exact PCI leaf asks about privileged mode, which aws.b.codebuild.nonprivileged tests. Secret-indicator content does not evaluate environment.privilegedMode.'}
        return {'recommendation': 'retain_existing_name_predicate', 'reason': 'CodeBuild.2 names AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. Content-indicator scanning can miss unrecognized values under those names, so it must not replace the existing environment-name test.'}
    if source_id == 'ecs_task_definitions_no_environment_secrets':
        return {'recommendation': 'propose_add_partial_signal', 'reason': 'This exact leaf asks whether secrets are passed as container environment variables. The admitted content-indicator check supplements credential-name matching, but selected indicator absence is not proof of absence of all secrets; change the requirement to PARTIAL if adding this limited support.'}
    if source_id.startswith('kms_key_enclave_'):
        return {'recommendation': 'propose_add_partial_signal', 'reason': 'The exact leaf currently declares NEW_CHECK for this enclave predicate; the newly admitted same-source native is relevant. Attach only with PARTIAL assurance because inventory selection and, for debug detection, bounded event-window completeness remain limitations.'}
    if source_id == 'ec2_instance_secrets_user_data':
        if fid == 'iso27001_2022_aws':
            reason = 'This exact leaf concerns network security/service mechanisms. User-data secret indicators do not establish network protection or network-service requirements; preserve only the upstream topic association.'
            recommendation = 'retain_topic_only'
        elif fid.startswith('kisa_') and rid == '2.7.1':
            reason = 'The exact leaf requires an encryption policy and applied encryption. User-data indicator scanning neither evaluates cryptographic strength nor proves encryption at storage or transport; preserve the source topic only.'
            recommendation = 'retain_topic_only'
        else:
            reasons = {
                ('aws_ai_security_framework_aws', 'AISF-DATA-05'): 'Hardcoded-secret detection is directly relevant to the named EC2 AI workload surface; selected indicators do not cover Lambda/ECS, every secret, or prove AI-workload inventory.',
                ('aws_well_architected_framework_security_pillar_aws', 'SEC02-BP03'): 'An observed embedded secret is a credential-handling signal; it does not establish workload identity proof, purpose-built retrieval, lifecycle or rotation.',
                ('mitre_attack_aws', 'T1552'): 'Observed user-data secrets are directly relevant to insecurely stored credentials; filesystem repositories, private keys and other credential locations remain outside this bounded scan.',
                ('nist_csf_2.0_aws', 'ds_5'): 'Embedded-secret indicators support the data-leak topic; DLP enforcement, exfiltration paths and leak-response records remain unverified.',
                ('secnumcloud_3.2_aws', '10.5'): 'User-data secret indicators support secure storage of secrets; generation, distribution, rotation and destruction remain unverified.',
            }
            reason = reasons.get(key, 'The exact KISA cloud-security leaf includes configuration errors exposing sensitive information. Selected user-data indicators contribute one narrow cloud configuration signal; documented controls, administrator access and complete workload scope remain unverified.')
            recommendation = 'propose_add_partial_signal'
        return {'recommendation': recommendation, 'reason': reason}
    return {'recommendation': 'needs_individual_review', 'reason': 'No directed semantic decision has been authored for this new divergence.'}


def assurance_corrections(requirements):
    """Individually source-inspected predicate families, with exact preconditions."""
    result = []
    for framework in requirements['frameworks']:
        if framework['provider'] != 'aws':
            continue
        for row in framework['requirements']:
            checks = row['native_checks']
            correction = None
            if ('aws.claude_a.iam.no_unused_initial_access_key' in checks
                    and framework['id'].startswith('cis_') and row['runtime_status'] == 'automated'):
                correction = {
                    'operation': 'replace_requirement_assurance', 'decision': 'PARTIAL',
                    'runtime_status': 'partial',
                    'reason': 'Never-used active keys for console users are an observed hygiene signal. A key created at initial user setup can later be used and pass this predicate; initial-setup timing and historical deleted keys need lifecycle evidence.',
                    'counterexample': 'Console user with a key created during initial setup and subsequently used passes no_initial_key.',
                    'predicate': 'peaso/checks/claude_aws_a_iam.py:no_initial_key',
                    'official_reference': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html'}
            elif (framework['id'] == 'aws-compliance.benchmark.cis_v130'
                  and row['requirement_id'] == 'aws-compliance.control.cis_v130_1_7'
                  and row['runtime_status'] == 'automated'):
                correction = {
                    'operation': 'replace_requirement_assurance', 'decision': 'PARTIAL',
                    'runtime_status': 'partial',
                    'reason': 'Ninety-day root inactivity is a bounded signal. It does not establish the ongoing practice of eliminating root administration or document exceptional root use; retain owner/process review as in adjacent CIS versions.',
                    'counterexample': 'Root administration 91 days before capture passes a 90-day inactivity predicate.',
                    'predicate': 'peaso/checks/aws_gap_core.py:root_not_used_90_days',
                    'official_reference': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html'}
            elif ('aws.pci.vpc.world_ingress_authorized_ports' in checks
                  and 'tests attachment to AWS-managed ENIs' in row['reason']):
                correction = {
                    'operation': 'replace_requirement_reason',
                    'decision': row['decision'], 'runtime_status': row['runtime_status'],
                    'reason': 'The current _world evaluator compares IPv4/IPv6 world ingress TCP/UDP ranges against supplied approved_ports; all-protocol ingress fails and unavailable approval input remains unknown. This automates comparison with a supplied policy, while approval provenance is an external input.',
                    'predicate': 'peaso/checks/compliance_new_sw41.py:_world',
                    'official_reference': 'https://docs.aws.amazon.com/config/latest/developerguide/vpc-sg-open-only-to-authorized-ports.html'}
            if correction:
                result.append(dict(correction, framework_id=framework['id'],
                                   requirement_id=row['requirement_id'],
                                   native_checks=checks, previous_decision=row['decision'],
                                   previous_runtime_status=row['runtime_status'],
                                   previous_reason=row['reason']))
    return result


def audit(root, cache):
    captured = {name: (root / 'peaso/rulepacks' / name).read_bytes() for name in
                ('native_catalog.json', 'compliance_requirements.json', 'upstream_manifest.json')}
    native = json.loads(captured['native_catalog.json'])
    active = {c['id']: c for c in native['checks'] if c['provider'] == 'aws'}
    requirements = json.loads(captured['compliance_requirements.json'])
    compiled = {(f['id'], r['requirement_id']): r for f in requirements['frameworks']
                if f['provider'] == 'aws' for r in f['requirements']}
    ledger, ledger_inputs = verified_ledgers(root)
    decision_path = root / 'docs/aws-review/requirement-decisions.json'
    accepted = {}
    if decision_path.exists():
        document = read(decision_path)
        if document.get('schema_version') != 1:
            raise ValueError('Invalid requirement decision review')
        ledger_inputs[str(decision_path.relative_to(root))] = sha(decision_path)
        accepted = {(d.get('source_id'), d.get('framework_id'), d.get('requirement_id')): d
                    for d in document['decisions'] if d.get('source_id')}
    manifest = json.loads(captured['upstream_manifest.json'])
    source_natives = defaultdict(set)
    for row in manifest['checks']:
        if row.get('repository') == 'prowler-cloud/prowler' and row['provider'] == 'aws':
            source_natives[row['upstream_id']].update(set(row.get('native_checks', [])) & active.keys())
    tree = read(cache / 'tree.json')
    if tree.get('truncated'):
        raise ValueError('Truncated upstream tree')
    documents = {Path(e['path']).stem: json.loads(verified_bytes(cache, e)) for e in tree['tree']
                 if e['path'].startswith('prowler/compliance/aws/') and e['path'].endswith('.json')}
    refs = compliance_index(documents)
    source_definitions = definitions(documents)
    edges, family_sources = [], defaultdict(set)
    for entry in tree['tree']:
        path = entry['path']
        if path.startswith(PREFIX) and path.endswith('.metadata.json'):
            meta = json.loads(verified_bytes(cache, entry))
            sid = meta['CheckID']
            family_sources[path[len(PREFIX):].split('/')[0]].add(sid)
    for sid, ids in sorted(source_natives.items()):
        if not ids:
            continue
        current = {(t['framework_id'], t['requirement_id']) for cid in ids
                   for t in active[cid].get('requirement_controls', [])}
        for key in sorted(refs.get(sid, set()) - current):
            edges.append(reconcile_edge(sid, ids, key, ledger, compiled, accepted))
    evidence = []
    for key in sorted({(e['framework_id'], e['requirement_id']) for e in edges}):
        row = ledger.get(key)
        evidence.append({'framework_id': key[0], 'requirement_id': key[1],
                         'source_definition': source_definitions.get(key),
                         'canonical': row,
                         'compiled': compiled.get(key)})
    families = []
    for family, sources in sorted(family_sources.items()):
        ids = sorted({cid for sid in sources for cid in source_natives[sid]})
        families.append({'service': family, 'source_ids': sorted(sources),
                         'active_native_ids': ids,
                         'source_ids_without_active_native': sorted(s for s in sources if not source_natives[s]),
                         'coverage_claim': 'source-linked inventory only; not exhaustive security assurance'})
    counts = Counter(e['disposition'] for e in edges)
    corrections = assurance_corrections(requirements)
    for correction in corrections:
        key = (correction['framework_id'], correction['requirement_id'])
        correction['canonical_ledger'] = ledger[key]['ledger']
        correction['canonical_precondition'] = {k: ledger[key].get(k) for k in ('decision', 'reason', 'native_checks')}
        correction['canonical_review_status'] = ('accepted_awaiting_catalog_refresh'
            if ledger[key]['decision'] == correction['decision'] and ledger[key]['reason'] == correction['reason']
            else 'proposed')
    inputs = {name: hashlib.sha256(data).hexdigest() for name, data in captured.items()}
    if any(sha(root / path) != digest for path, digest in ledger_inputs.items()):
        raise RuntimeError('Canonical ledger changed during audit')
    return {'schema_version': 1, 'scope': 'Every active AWS ID, pinned Prowler requirement association, and upstream service family',
            'upstream': read(cache / 'revision.json'), 'input_sha256': inputs,
            'ledger_input_sha256': ledger_inputs,
            'summary': {'active_aws_ids': len(active), 'upstream_service_families': len(families),
                        'divergent_upstream_ids': len({e['source_id'] for e in edges}),
                        'divergent_edges': len(edges), 'distinct_requirements': len(evidence),
                        'edge_dispositions': dict(sorted(counts.items())),
                        'unresolved_edges': sum(n for k, n in counts.items() if k.startswith('unresolved')),
                        'unresolved_requirements': len({(e['framework_id'], e['requirement_id']) for e in edges if e['disposition'].startswith('unresolved')}),
                        'proposed_corrections': len(corrections)},
            'limitations': ['Each edge was reconciled against its exact source definition and canonical ledger; unresolved additional-signal semantics are not individually accepted.',
                            'Canonical rejection/manual scope resolves membership decisions, not predicate equivalence.',
                            'Source-topic proposals must not enter compliance status aggregation.',
                            'No cloud calls, upstream execution, deployment, or UI acceptance.'],
            'proposed_corrections': corrections, 'requirement_evidence': evidence,
            'association_divergences': edges, 'service_families': families,
            'all_active_ids': sorted(active),
            'active_resource_kinds': [{'kind': kind, 'ids': sorted(c['id'] for c in active.values() if c['type'] == kind)}
                                      for kind in sorted({c['type'] for c in active.values()})],
            'active_ids_without_current_prowler_lineage': sorted(set(active) - {cid for ids in source_natives.values() for cid in ids})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--cache', type=Path, default=Path('/tmp/peasso-aws-review-20261019/prowler/head-20261019-140026'))
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/aws-review/requirement-associations.json')
    args = parser.parse_args()
    report = audit(args.root, args.cache)
    if any(sha(args.root / 'peaso/rulepacks' / name) != digest for name, digest in report['input_sha256'].items()):
        raise RuntimeError('Catalog changed during audit')
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
