import json
from pathlib import Path
import copy
import pytest
from peaso import privesc
from peaso.privesc.effective_permissions.principal_evidence import CONTRACT,TRUST_SERVICES,fingerprint
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_v4_batch import _snapshot,_required_actions
from tests.test_peaso_privesc_schema_ext import reached
ENTRIES=[{k:v for k,v in e.items()if k!='_file'}for e in privesc.load_catalog()['entries']if e['id']in json.loads(Path('peaso/privesc/exact_principal_tranche.json').read_text())]


def case(entry):
    snap=_snapshot(entry);snap['created_at']='2026-10-14T12:30:00Z'
    kind=entry['provider']+'_privesc_challenge_evidence';col=next(c for c in snap['collections']if c['type']==kind);fact=col['items'][0]
    if entry['provider']=='aws':
        source=fact['SourceArn'];target=fact['TargetId']
        role=next(c for c in snap['collections']if c['type']=='iam_role')['items'][0]
        role['AssumeRolePolicyDocument']={'Statement':[{'Effect':'Allow','Principal':{'Service':TRUST_SERVICES[entry['id']]},'Action':'sts:AssumeRole'}]}
        role['RolePolicyList']=[{'PolicyName':'target','PolicyDocument':{'Statement':[{'Effect':'Allow','Action':'iam:ListUsers','Resource':'*'}]}}]
        bindings={action:[target if action.lower()=='iam:passrole'else '*'if action.lower()=='iot:registercertificatewithoutca'else 'arn:aws:'+('ssm'if action.startswith('ssm:')else 'devicefarm'if action.startswith('devicefarm:')else 'iot')+':us-east-1:111111111111:resource/execution']for action in _required_actions(entry.get('requires',{}))}
        cred='aws_workload_identity'
    else:source=fact['SourceId'];target=fact['TargetId'];bindings={};cred='gcp_oauth_access_token'
    fact.update(EvidenceRef='reviewed-runtime-and-authorization-proof',CredentialUsable=True,FullPrincipalAuthorityVerified=True,SessionRestricted=False,
                CredentialSubjectId=target,RevocationChecked=True,CredentialKind=cred,VerifiedConditionIds=CONTRACT[entry['id']]['conditions'],
                EvidenceObservedAt='2026-10-14T12:29:00Z',CredentialExpiresAt='2026-10-14T12:40:00Z',ActionResources=bindings,
                AuthorizationFingerprint=fingerprint(snap,entry['provider'],target))
    if entry['provider']=='gcp':fact['OAuthScopes']=['https://www.googleapis.com/auth/cloud-platform']
    return snap,source,col


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
def test_exact_native_subject_and_full_authority_is_only_conditional(entry):
    assert validate_entry(entry)[0]==[]
    snap,source,col=case(entry);before=copy.deepcopy(snap)
    got=reached(privesc.analyze(snap,entries=[entry]),source,entry['id'])
    assert got=={col['items'][0]['TargetId']:'conditional'},(entry['id'],got)
    assert snap==before


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
def test_scoped_expired_wrong_subject_or_changed_rights_never_reach_full_identity(entry):
    for mutation in ({'FullPrincipalAuthorityVerified':False},{'SessionRestricted':True},{'CredentialUsable':False},{'CredentialSubjectId':'another-identity'},
                     {'AuthorizationFingerprint':'changed'},{'EvidenceRef':''},{'RevocationChecked':False},{'VerifiedConditionIds':['missing']},
                     {'CredentialExpiresAt':'2026-10-14T12:29:59Z'},{'EvidenceObservedAt':'2026-10-14T12:30:01Z'},
                     {'CredentialKind':'oidc_audience_bound_token'}):
        snap,source,col=case(entry);col['items'][0].update(mutation)
        assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values(),(entry['id'],mutation)
    snap,source,col=case(entry);col['items']*=2
    assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()
    snap,source,col=case(entry);col['status']='partial'
    assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()


@pytest.mark.parametrize('entry',[e for e in ENTRIES if e['provider']=='aws'],ids=lambda e:e['id'])
def test_principal_attestation_does_not_replace_action_resource_permissions_or_role_trust(entry):
    snap,source,col=case(entry)
    next(c for c in snap['collections']if c['type']=='iam_user')['items'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'][0]['Resource']='arn:aws:ssm:us-east-1:111111111111:resource/other'
    assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()
    snap,source,col=case(entry);next(c for c in snap['collections']if c['type']=='iam_role')['items'][0]['AssumeRolePolicyDocument']={'Statement':[]}
    col['items'][0]['AuthorizationFingerprint']=fingerprint(snap,'aws',col['items'][0]['TargetId'])
    assert 'conditional'not in reached(privesc.analyze(snap,entries=[entry]),source,entry['id']).values()
