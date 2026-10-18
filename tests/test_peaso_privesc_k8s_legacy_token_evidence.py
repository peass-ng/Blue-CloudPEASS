"""Secret metadata alone cannot turn a Kubernetes Secret read into an SA edge."""
import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.effective_permissions.credential_evidence import (
    LEGACY_SA_TOKEN, LEGACY_SA_CONDITIONS, CREATED_SA_TOKEN, CREATED_SA_CONDITIONS,
)
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import DEV, crole, k8s_snap, rb, sa, secret, user

ENTRY = next(e for e in yaml.safe_load(Path('peaso/privesc/catalog/k8s/rbac.yaml').read_text())
             if e['id'] == LEGACY_SA_TOKEN)
ENTRY_CREATE = next(e for e in yaml.safe_load(Path('peaso/privesc/catalog/k8s/rbac.yaml').read_text())
                    if e['id'] == CREATED_SA_TOKEN)
TARGET = 'k8s:c1:sa:prod:api'


def case():
    token = secret('api-token', 'prod', 'kubernetes.io/service-account-token')
    token['metadata'].update(uid='uid-1', resourceVersion='17', annotations={'kubernetes.io/service-account.name': 'api'})
    role = crole('reader', [{'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['get']}])
    snap = k8s_snap(clusterroles=[role], rbs=[rb('read', 'prod', 'reader', user('dev'))],
                    sas=[sa('api', 'prod')], namespaces=('prod',), secrets=[token])
    snap['created_at'] = '2026-10-14T19:00:00Z'
    fact = {'TechniqueId': LEGACY_SA_TOKEN, 'SourceId': DEV, 'TargetKind': 'k8s_service_account',
            'TargetId': TARGET, 'TargetScope': 'c1', 'Status': 'verified', 'VerifiedPreconditions': True,
            'EvidenceRef': 'reviewed-token-1', 'CredentialUsable': True, 'RevocationChecked': True,
            'CredentialKind': 'k8s_bearer_token', 'CredentialSubjectId': 'system:serviceaccount:prod:api',
            'CredentialScope': 'c1', 'CredentialAudience': 'https://cluster.example.invalid',
            'ApiServerAcceptedAudience': 'https://cluster.example.invalid',
            'ApiServerTokenAccepted': True, 'EffectiveRights': ['get:pods:prod'],
            'NewEffectivePermission': 'get:pods:prod', 'SourcePreviouslyDenied': True,
            'EvidenceObservedAt': '2026-10-14T18:59:00Z', 'CredentialExpiresAt': '2026-10-14T19:10:00Z',
            'VerifiedConditionIds': list(LEGACY_SA_CONDITIONS), 'SecretName': 'api-token',
            'SecretNamespace': 'prod', 'SecretUID': 'uid-1', 'SecretResourceVersion': '17',
            'SecretReadAction': 'get', 'SecretReadAccepted': True}
    snap['collections'].append({'type': 'k8s_privesc_challenge_evidence', 'scope': 'c1',
                                'status': 'collected', 'items': [fact], 'error': None, 'service': 'privesc'})
    return snap, fact


def test_exact_accepted_token_is_a_conditional_path_and_snapshot_unchanged():
    snap, _ = case()
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[ENTRY])
    assert reached(result, DEV, LEGACY_SA_TOKEN) == {TARGET: 'conditional'}
    assert snap == before


@pytest.mark.parametrize('change', [
    {'SourceId': 'other'}, {'TargetId': 'other'}, {'SecretName': 'other'}, {'SecretUID': 'other'},
    {'SecretResourceVersion': '18'}, {'CredentialSubjectId': 'system:serviceaccount:prod:other'},
    {'CredentialAudience': 'other'}, {'ApiServerTokenAccepted': False}, {'SecretReadAccepted': False},
    {'CredentialUsable': False}, {'EffectiveRights': []}, {'VerifiedConditionIds': []},
    {'SourcePreviouslyDenied': False}, {'NewEffectivePermission': 'get:secrets:prod'},
    {'SecretReadAction': 'delete'}, {'Status': 'disproven'}, {'EvidenceObservedAt': '2026-10-14T18:30:00Z'},
])
def test_partial_or_mismatched_proof_yields_no_path(change):
    snap, fact = case()
    fact.update(change)
    assert not reached(privesc.analyze(snap, entries=[ENTRY]), DEV, LEGACY_SA_TOKEN)


def test_missing_or_duplicate_proof_and_inert_secret_yield_no_path():
    snap, fact = case()
    snap['collections'][-1]['items'] = []
    assert not reached(privesc.analyze(snap, entries=[ENTRY]), DEV, LEGACY_SA_TOKEN)
    snap['collections'][-1]['items'] = [fact, copy.deepcopy(fact)]
    assert not reached(privesc.analyze(snap, entries=[ENTRY]), DEV, LEGACY_SA_TOKEN)
    snap['collections'][-1]['items'] = [fact]
    snap['collections'][-2]['items'][0]['type'] = 'Opaque'
    assert not reached(privesc.analyze(snap, entries=[ENTRY]), DEV, LEGACY_SA_TOKEN)


def test_wrong_secret_permission_and_partial_metadata_yield_no_path():
    snap, _ = case()
    role = next(c for c in snap['collections'] if c['type'] == 'clusterrole')['items'][0]
    role['rules'][0]['verbs'] = ['patch']
    assert not reached(privesc.analyze(snap, entries=[ENTRY]), DEV, LEGACY_SA_TOKEN)
    snap, _ = case()
    next(c for c in snap['collections'] if c['type'] == 'secret_metadata')['status'] = 'partial'
    assert not reached(privesc.analyze(snap, entries=[ENTRY]), DEV, LEGACY_SA_TOKEN)


def test_created_token_requires_admitted_populated_secret_and_new_permission():
    snap, fact = case()
    next(c for c in snap['collections'] if c['type'] == 'clusterrole')['items'][0]['rules'][0]['verbs'] = ['create', 'get']
    fact.update(TechniqueId=CREATED_SA_TOKEN, VerifiedConditionIds=list(CREATED_SA_CONDITIONS),
                SecretCreateAccepted=True, TokenControllerPopulated=True)
    assert reached(privesc.analyze(snap, entries=[ENTRY_CREATE]), DEV, CREATED_SA_TOKEN) == {TARGET: 'conditional'}
    for change in ({'SecretCreateAccepted': False}, {'TokenControllerPopulated': False},
                   {'SourcePreviouslyDenied': False}, {'NewEffectivePermission': 'other'}):
        modified = copy.deepcopy(snap)
        modified['collections'][-1]['items'][0].update(change)
        assert not reached(privesc.analyze(modified, entries=[ENTRY_CREATE]), DEV, CREATED_SA_TOKEN)
    modified = copy.deepcopy(snap)
    next(c for c in modified['collections'] if c['type'] == 'clusterrole')['items'][0]['rules'][0]['verbs'] = ['get']
    assert not reached(privesc.analyze(modified, entries=[ENTRY_CREATE]), DEV, CREATED_SA_TOKEN)
