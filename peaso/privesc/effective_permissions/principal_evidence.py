"""Full-principal attestation is distinct from a bounded session or application token."""
import hashlib
import json
from datetime import datetime,timezone
from pathlib import Path
import re
from . import items,inventory_status
CONTRACT=json.loads(Path(__file__).resolve().parents[1].joinpath('exact_principal_tranche.json').read_text())
BULK_CONTRACT=json.loads(Path(__file__).resolve().parents[1].joinpath('bulk_principal_tranche.json').read_text())
CONTRACT={**CONTRACT,**BULK_CONTRACT}


def fingerprint(snapshot,provider,target):
    if provider=='aws':
        roles=[row for _,row in items(snapshot,'iam_role')if row.get('Arn')==target]
        if len(roles)!=1:return None
        essential=['Arn','RolePolicyList','AttachedManagedPolicies','PermissionsBoundary','AssumeRolePolicyDocument']
        principal={k:v for k,v in roles[0].items()if k in essential}
        policies=[{k:v for k,v in row.items()if k in ('Arn','PolicyVersionList','DefaultVersionId')}for _,row in items(snapshot,'iam_policy')]
        value={'principal':principal,'policies':sorted(policies,key=lambda r:r.get('Arn',''))}
    else:
        email=target.removeprefix('serviceAccount:')
        accounts=[row for _,row in items(snapshot,'service_account')if row.get('email')==email]
        if len(accounts)!=1 or accounts[0].get('disabled')is True:return None
        value={'principal':accounts[0], 'policies':[(scope,row)for scope,row in items(snapshot,'iam_policy')],
               'roles':[(scope,row)for scope,row in items(snapshot,'iam_role')]}
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()


def required_paths(value):
    # Exact source action/resource checks supplement the catalog's broad prefilter.
    if not isinstance(value,dict):return []
    from ..schema import expand_requires
    return expand_requires(value)
    common=value.get('all_of',[])
    alternatives=value.get('any_of',[])
    return [common+group for group in alternatives]if alternatives else [common]


def valid(snapshot,technique,fact,source,target,scope):
    spec=CONTRACT[technique];provider=spec['provider']
    if (fact.get('TechniqueId')!=technique or fact.get('TargetKind')!=spec['target_kind']or fact.get('TargetId')!=target
        or fact.get('Status')!='verified'or fact.get('VerifiedPreconditions')is not True or fact.get('CredentialUsable')is not True
        or fact.get('FullPrincipalAuthorityVerified')is not True or fact.get('SessionRestricted')is not False
        or fact.get('CredentialSubjectId')!=target or fact.get('RevocationChecked')is not True):return False
    if provider=='aws':
        if fact.get('SourceArn')!=source or fact.get('TargetAccount')!=scope:return False
        if not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::'+re.escape(scope)+r':role/.+',target):return False
    elif fact.get('SourceId')!=source or fact.get('TargetScope')!=scope:return False
    if not isinstance(fact.get('EvidenceRef'),str)or not fact['EvidenceRef'].strip():return False
    conditions=fact.get('VerifiedConditionIds')
    if not isinstance(conditions,list)or any(not isinstance(c,str)for c in conditions)or sorted(conditions)!=spec['conditions']:return False
    expected=fingerprint(snapshot,provider,target)
    if not isinstance(expected,str)or fact.get('AuthorizationFingerprint')!=expected:return False
    if provider=='gcp'and fact.get('CredentialKind')not in ('gcp_service_account_private_key','gcp_oauth_access_token'):return False
    if provider=='gcp'and fact.get('CredentialKind')=='gcp_oauth_access_token'and fact.get('OAuthScopes')!=['https://www.googleapis.com/auth/cloud-platform']:return False
    if provider=='aws'and fact.get('CredentialKind')not in ('aws_role_session','aws_workload_identity'):return False
    def instant(value):
        if not isinstance(value,str):raise ValueError('missing timestamp')
        result=datetime.fromisoformat(value.replace('Z','+00:00'))
        if result.tzinfo is None:raise ValueError('naive timestamp')
        return result
    try:
        captured=instant(snapshot.get('created_at'));observed=instant(fact.get('EvidenceObservedAt'));expiry=instant(fact.get('CredentialExpiresAt'))
        return observed<=captured<expiry and (captured-observed).total_seconds()<=900
    except (ValueError,TypeError):return False


def check_bindings(model,technique,fact,source):
    bindings=fact.get('ActionResources')
    if not isinstance(bindings,dict):return False
    normalized={str(k).lower():v for k,v in bindings.items()}
    if len(normalized)!=len(bindings):return False
    for path in required_paths(CONTRACT[technique]['requires']):
        valid_path=True
        for requirement in path:
            action=requirement.get('action')
            if not isinstance(action,str):valid_path=False;break
            resources=normalized.get(action.lower())
            if not isinstance(resources,list)or not resources or any(not isinstance(r,str)or not r for r in resources):valid_path=False;break
            for resource in resources:
                if model.provider=='aws':
                    if resource=='*':
                        if action.lower()!='iot:registercertificatewithoutca'and not CONTRACT[technique].get('allow_global_source_bindings'):valid_path=False;break
                    elif '*'in resource or '?'in resource or not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:[a-z0-9-]*:'+re.escape(source.scope)+r':.+',resource):valid_path=False;break
                    grant=model._check_action(source,action.lower(),resource)
                else:
                    if '*'in resource or '?'in resource:valid_path=False;break
                    grant=model.check(source,{'action':action},resource)
                if grant is None or grant.confidence=='unknown':valid_path=False;break
            if not valid_path:break
        if valid_path:return True
    return False


TRUST_SERVICES={
 'aws-audit-use-existing-parameterized-automation-runbook-with-runtime-passrole':'ssm.amazonaws.com',
 'aws-codebuild-ssm-debug-session-role':'codebuild.amazonaws.com',
 'aws-devicefarm-schedulerun-existing-test-spec-passrole':'devicefarm.amazonaws.com',
 'aws-iot-byo-certificate-existing-rolealias':'credentials.iot.amazonaws.com',
 'aws-iot-provisioning-claim-existing-rolealias':'credentials.iot.amazonaws.com',
}
