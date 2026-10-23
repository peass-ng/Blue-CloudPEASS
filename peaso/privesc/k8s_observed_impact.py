"""Plain impact lines for each reviewed Kubernetes privilege path."""

import json
from pathlib import Path
import re


_IMPACT = json.loads(Path(__file__).with_suffix('.json').read_text())


def format_path(check_id, status, summary, source_label):
    lines = _IMPACT.get(check_id, {}).get(status)
    if not lines or not isinstance(summary, str):
        return summary
    fact = re.split(r'(?<=[.!?])\s+', summary, maxsplit=1)[0]
    if check_id == 'k8s-rbac-csr-kube-apiserver-client-serviceaccount':
        fact = ('The usable CSR name and the ServiceAccount binding are not fully recorded.'
                if status == 'UNKNOWN' else
                'The source has CSR create, read and approval grants for the kube-apiserver-client signer.')
    if check_id == 'k8s-configconnector-service-account-key':
        fact = (f'The watched namespace, key-resource permission, or target Google service account for {source_label} is missing or unresolved.'
                if status == 'UNKNOWN' else
                f'{source_label} has recorded key-resource access in a Config Connector watched namespace.')
    if check_id == 'k8s-configconnector-project-iam-grant':
        fact = (f'The watched namespace, IAM-resource permission, or controller project access for {source_label} is missing or unresolved.'
                if status == 'UNKNOWN' else
                f'{source_label} has recorded Config Connector IAM-resource access in a watched namespace.')
    if check_id in {
        'k8s-rbac-constrained-impersonation-user',
        'k8s-rbac-constrained-impersonation-serviceaccount',
        'k8s-rbac-constrained-impersonation-node',
        'k8s-rbac-constrained-impersonation-associated-node',
    }:
        if status == 'UNKNOWN':
            fact = f'The impersonate-on grant or target action for {source_label} is missing or not fully recorded.'
        elif ' reach ' in fact:
            target = fact.split(' reach ', 1)[1].rstrip('.')
            fact = f'The recorded impersonate-on grant for {source_label} matches an action of {target}.'
    if status == 'MANUAL' and fact.startswith('The recorded grants may let ') and fact.endswith('.'):
        actor_target = fact.removeprefix('The recorded grants may let ').removesuffix('.')
        if ' reach ' in actor_target:
            actor, target = actor_target.split(' reach ', 1)
            fact = f'The recorded grants link {actor} to {target}, with remaining conditions.'
    if check_id == 'analysis.coverage' and fact.startswith('The scan lacks complete records for '):
        fact = 'The resource inventory is incomplete for ' + fact.removeprefix('The scan lacks complete records for ')
    if check_id in {'analysis.inactive_identity', 'analysis.network_review'} and ';' in fact:
        fact = fact.split(';', 1)[0].rstrip('. ') + '.'
    actor = source_label if isinstance(source_label, str) and len(source_label) <= 80 else 'the source identity'
    meaning, impact = (line.replace('alice', actor) for line in lines)
    return '\n'.join((fact, meaning, impact))
