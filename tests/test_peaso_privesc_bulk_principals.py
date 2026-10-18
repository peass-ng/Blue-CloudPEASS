import copy,json
from pathlib import Path
import pytest
from peaso import privesc
from peaso.privesc.schema import validate_entry
from peaso.privesc.versioned_catalog import _verified_prior
from peaso.privesc.effective_permissions.principal_evidence import BULK_CONTRACT,fingerprint,required_paths
from tests.test_peaso_privesc_v4_batch import _snapshot
from tests.test_peaso_privesc_schema_ext import reached
ENTRIES=[{k:v for k,v in e.items()if k!='_file'}for e in privesc.load_catalog()['entries']if e['id']in BULK_CONTRACT]

def case(e):
 s=_snapshot(e);s['created_at']='2026-10-14T12:30:00Z';c=next(c for c in s['collections']if c['type']==e['provider']+'_privesc_challenge_evidence');f=c['items'][0];p=BULK_CONTRACT[e['id']];actions=[r['action']for r in required_paths(p['requires'])[0]]
 if e['provider']=='aws':
  source=f['SourceArn'];next(c for c in s['collections']if c['type']=='iam_user')['items'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'][0]['Action']=actions or['iam:ListUsers'];bindings={a:['*']for a in actions};kind='aws_role_session'
 else:
  source=f['SourceId'];next(c for c in s['collections']if c['type']=='iam_role')['items'][0]['includedPermissions']=actions;bindings={a:['projects/p1']for a in actions};kind='gcp_oauth_access_token'
 f.update(EvidenceRef='exact-reviewed-full-principal-proof',CredentialUsable=True,FullPrincipalAuthorityVerified=True,SessionRestricted=False,CredentialSubjectId=f['TargetId'],RevocationChecked=True,CredentialKind=kind,VerifiedConditionIds=p['conditions'],EvidenceObservedAt='2026-10-14T12:29:00Z',CredentialExpiresAt='2026-10-14T12:40:00Z',ActionResources=bindings,AuthorizationFingerprint=fingerprint(s,e['provider'],f['TargetId']))
 if e['provider']=='gcp':f['OAuthScopes']=['https://www.googleapis.com/auth/cloud-platform']
 return s,source,c

@pytest.mark.parametrize('entry',ENTRIES or [None],ids=lambda e:e['id'] if e is not None else 'no-active-entries')
def test_full_principal_path_needs_current_exact_source_subject_and_permissions(entry):
 if entry is None:
  assert ENTRIES == []
  assert len(ARCHIVED_BULK_ENTRIES) == len(BULK_CONTRACT) == 98
  return
 assert validate_entry(entry)[0]==[]
 s,source,c=case(entry);before=copy.deepcopy(s);got=reached(privesc.analyze(s,entries=[entry]),source,entry['id']);assert got=={c['items'][0]['TargetId']:'conditional'},(entry['id'],got);assert s==before
 for update in ({'CredentialUsable':False},{'FullPrincipalAuthorityVerified':False},{'SessionRestricted':True},{'CredentialSubjectId':'wrong'},{'AuthorizationFingerprint':'wrong'},{'EvidenceRef':''},{'RevocationChecked':False},{'CredentialExpiresAt':'2026-10-14T12:29:00Z'},{'EvidenceObservedAt':'2026-10-14T12:31:00Z'},{'VerifiedConditionIds':[]},{'ActionResources':{}},{'CredentialKind':'audience_bound_token'}):
  x=copy.deepcopy(s);next(env for env in x['collections']if env['type']==entry['provider']+'_privesc_challenge_evidence')['items'][0].update(update);assert 'conditional'not in reached(privesc.analyze(x,entries=[entry]),source,entry['id']).values(),(entry['id'],update)
 x=copy.deepcopy(s);next(env for env in x['collections']if env['type']==entry['provider']+'_privesc_challenge_evidence')['items']*=2;assert 'conditional'not in reached(privesc.analyze(x,entries=[entry]),source,entry['id']).values()
 x=copy.deepcopy(s);next(env for env in x['collections']if env['type']==entry['provider']+'_privesc_challenge_evidence')['status']='partial';assert 'conditional'not in reached(privesc.analyze(x,entries=[entry]),source,entry['id']).values()


# Exercise the exact reviewed historical techniques against the pinned archive.
# Active per-entry tests run automatically if any enter the current catalog.
_ARCHIVED, _ = _verified_prior()
ARCHIVED_BULK_ENTRIES = [{k: v for k, v in _ARCHIVED[ident].items() if k != "_file"}
                         for ident in BULK_CONTRACT]


@pytest.mark.parametrize("entry", ARCHIVED_BULK_ENTRIES, ids=lambda e: e["id"])
def test_archived_bulk_principal_path_preserves_full_evidence_contract(entry):
    test_full_principal_path_needs_current_exact_source_subject_and_permissions(entry)
