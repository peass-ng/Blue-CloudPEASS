"""Exact EC2 profile-attachment branches, gated by separately reviewed instance control.

Native metadata establishes current attachment and target profile membership. It
never establishes that an IAM principal controls an instance or can obtain IMDS
credentials. No profile mutation or credential request is executed.
"""
from datetime import datetime
import re

from . import Grant, best, combine, downgrade

TECHNIQUE = 'aws-ec2-passrole-associate-instance-profile'


def _collection(snapshot, kind, scope):
    rows = [c for c in snapshot.get('collections', []) if c.get('type') == kind and c.get('scope') == scope]
    if len(rows) != 1 or rows[0].get('status') not in ('collected', 'empty') or not isinstance(rows[0].get('items'), list) or (rows[0].get('status')=='empty' and rows[0]['items']):
        raise ValueError('complete unique native collection unavailable')
    account, _, region = scope.partition('/')
    if ('account_id' in rows[0] and rows[0]['account_id'] != account) or (region != 'global' and 'region' in rows[0] and rows[0]['region'] != region):
        raise ValueError('collection account or region conflicts with scope')
    return rows[0]['items']


def _time(value):
    if not isinstance(value, str):raise ValueError('timestamp unavailable')
    stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
    if stamp.tzinfo is None:raise ValueError('timezone unavailable')
    return stamp


def _proof(snapshot, scope, source, role, profile, profile_id, instance):
    rows=_collection(snapshot,'aws_privesc_challenge_evidence',scope)
    records=[r for r in rows if r.get('TechniqueId')==TECHNIQUE and r.get('SourceId')==source
             and r.get('TargetId')==role and r.get('InstanceArn')==instance]
    if len(records)!=1:return False
    row=records[0]
    if (row.get('TargetKind')!='aws_role' or row.get('TargetScope')!=scope or row.get('TargetProfileArn')!=profile or row.get('TargetProfileId')!=profile_id
            or row.get('Status')!='verified' or row.get('InstanceControlled') is not True
            or row.get('ImdsRoleCredentialsReachable') is not True
            or row.get('VerifiedPreconditions') is not True
            or not isinstance(row.get('EvidenceRef'),str) or not row['EvidenceRef']):return False
    account, _, region = scope.partition('/')
    # An imported review record may carry additional exact identities. If it
    # does, a conflicting account, region or instance invalidates the proof.
    bindings={'SourceAccount':account,'TargetAccount':account,'Region':region,
              'InstanceId':instance.rsplit('/',1)[-1],'EvidenceScope':scope}
    if any(key in row and row[key] != expected for key,expected in bindings.items()):return False
    now=_time(snapshot.get('created_at'));observed=_time(row.get('EvidenceObservedAt'));expiry=_time(row.get('EvidenceExpiresAt'))
    return row['EvidenceRef'] if 0 <= (now-observed).total_seconds() <= 900 and now < expiry and (expiry-observed).total_seconds() <= 900 else None


def evaluate(evaluator, compiled):
    """Return only conditional exact native joins; unresolved inputs remain coverage."""
    from ..evaluator import Reach
    model=evaluator.model;snapshot=model.snapshot
    cset=evaluator.candidates(compiled)
    model.current_selector=compiled['selector'];model.current_cset=cset;model.current_entry=compiled['entry']
    reviewed_pairs={(r.get('SourceId'),r.get('TargetId')) for c in snapshot.get('collections',[])
                    if c.get('type')=='aws_privesc_challenge_evidence' and c.get('status')=='collected'
                    for r in c.get('items',[]) if isinstance(r,dict) and r.get('TechniqueId')==TECHNIQUE
                    and isinstance(r.get('SourceId'),str) and isinstance(r.get('TargetId'),str)}
    output=[]
    for source in sorted(evaluator.all_sources.values(),key=lambda n:n.id):
        if source.id in evaluator.service_managed_sources or evaluator._admin_covers(source,cset,compiled):continue
        if not any(s==source.id for s,_ in reviewed_pairs):continue
        targets={}
        for role_id,role in sorted(cset.members.items()):
            if (source.id,role_id) not in reviewed_pairs:continue
            if source.id==role_id or source.scope!=role.scope or role_id in cset.floor:continue
            profiles=role.attrs.get('instance_profiles')
            if not isinstance(profiles,list) or not profiles:continue
            for scope in snapshot.get('scopes',[]):
                match=re.fullmatch(r'([0-9]{12})/([a-z][a-z0-9-]+)',scope)
                if match is None or match[1]!=source.scope:continue
                account,region=match.groups();partition='aws-cn'if region.startswith('cn-')else'aws-us-gov'if region.startswith('us-gov-')else'aws'
                prefix=f'arn:{partition}:iam::{account}:'
                try:
                    roles=_collection(snapshot,'iam_role',account+'/global')
                    instances=_collection(snapshot,'instance',scope)
                    associations=_collection(snapshot,'ec2_instance_profile_association',scope)
                    role_rows=[r for r in roles if r.get('Arn')==role_id]
                    if len(role_rows)!=1 or not isinstance(role_rows[0].get('InstanceProfileList'),list):raise ValueError('target role inventory ambiguous')
                    mapping={};profile_ids={};profile_seen=set()
                    for native_role in roles:
                        arn=native_role.get('Arn')
                        if not isinstance(arn,str)or not re.fullmatch(re.escape(prefix)+r'role/[A-Za-z0-9_+=,.@/-]{1,512}',arn):raise ValueError('foreign IAM role')
                        for profile in native_role.get('InstanceProfileList',[]):
                            value=profile.get('Arn')
                            if not isinstance(value,str)or not re.fullmatch(re.escape(prefix)+r'instance-profile/[A-Za-z0-9_+=,.@/-]{1,512}',value):raise ValueError('foreign IAM profile')
                            members=profile.get('Roles');pid=profile.get('InstanceProfileId')
                            if (not isinstance(members,list) or len(members)!=1 or members[0].get('Arn')!=arn or not isinstance(native_role.get('RoleId'),str) or not native_role['RoleId'] or members[0].get('RoleId')!=native_role['RoleId']
                                    or not isinstance(pid,str) or not pid):raise ValueError('profile membership unavailable')
                            profile_ids[value]=pid
                            if value in profile_seen:raise ValueError('ambiguous profile membership')
                            profile_seen.add(value);mapping[value]=arn
                    seen_instances=set();by_instance={};seen_associations=set()
                    for assoc in associations:
                        iid,aid=assoc.get('InstanceId'),assoc.get('AssociationId')
                        if not isinstance(iid,str)or not re.fullmatch(r'i-[0-9a-f]{8,17}',iid)or not isinstance(aid,str)or not re.fullmatch(r'iip-assoc-[0-9a-f]{8,17}',aid)or aid in seen_associations:raise ValueError('association identity invalid')
                        seen_associations.add(aid);by_instance.setdefault(iid,[]).append(assoc)
                    for item in instances:
                        iid=item.get('InstanceId')
                        if not isinstance(iid,str)or not re.fullmatch(r'i-[0-9a-f]{8,17}',iid)or iid in seen_instances:raise ValueError('instance identity invalid')
                        seen_instances.add(iid)
                    if not set(by_instance)<=seen_instances:raise ValueError('orphan native association')
                    for item in instances:
                        iid=item['InstanceId'];instance=f'arn:{partition}:ec2:{region}:{account}:instance/{iid}'
                        if item.get('OwnerId',account)!=account or item.get('Arn',instance)!=instance:continue
                        state=item.get('State',{}).get('Name')
                        if state not in ('running','stopped'):continue
                        metadata=item.get('MetadataOptions',{})
                        if metadata.get('HttpEndpoint')!='enabled' or metadata.get('State')!='applied':continue
                        current=item.get('IamInstanceProfile');rows=by_instance.get(iid,[])
                        if current is None and not rows:branches=[('AssociateIamInstanceProfile',)]
                        elif isinstance(current,dict)and len(rows)==1 and rows[0].get('State')=='associated'and rows[0].get('IamInstanceProfile',{}).get('Arn')==current.get('Arn')and current.get('Arn')in mapping and current.get('Id')==rows[0].get('IamInstanceProfile',{}).get('Id')==profile_ids[current['Arn']]:
                            branches=([('ReplaceIamInstanceProfileAssociation',)] if state=='running' else [])+[
                                ('DisassociateIamInstanceProfile','AssociateIamInstanceProfile')]
                        else:continue
                        for profile in profiles:
                            if mapping.get(profile)!=role_id or (isinstance(current,dict)and current.get('Arn')==profile):continue
                            evidence=_proof(snapshot,scope,source.id,role_id,profile,profile_ids[profile],instance)
                            if not evidence:continue
                            passrole=model.check(source,{'action':'iam:PassRole','request_context':{'iam:AssociatedResourceArn':instance}},role_id)
                            if passrole is None or passrole.confidence!='derived':continue
                            for branch in branches:
                                grants=[passrole]
                                if state=='stopped':
                                    start=model.check(source,{'action':'ec2:StartInstances'},instance)
                                    if start is None or start.confidence!='derived':continue
                                    grants.append(start)
                                for operation in branch:
                                    context={}
                                    if operation!='DisassociateIamInstanceProfile':context['ec2:NewInstanceProfile']=profile
                                    # Associate follows a completed detach in the two-step branch.
                                    # AWS Quick Setup's published policy requires a null current profile.
                                    context['ec2:InstanceProfile']=({'absent':True} if operation=='AssociateIamInstanceProfile'
                                                                    else current['Arn'])
                                    grant=model.check(source,{'action':'ec2:'+operation,'request_context':context},instance)
                                    if grant is None or grant.confidence!='derived':break
                                    grants.append(grant)
                                else:
                                    grant=downgrade(combine(*grants),'conditional','reviewed_instance_control_and_IMDS_reachability')
                                    grant=Grant(grant.confidence,[*grant.refs,{'instance':instance,'profile':profile,'role':role_id,'branch':list(branch),'control_evidence':evidence}],grant.conditions)
                                    targets[role_id]=best(targets.get(role_id),grant)
                except (ValueError,TypeError,KeyError,AttributeError):
                    continue
        if targets:output.append(Reach(compiled,source,targets,cset))
    if not output:
        evaluator.note('technique','*','unresolved',TECHNIQUE+' exact native/control join unavailable',
                       'Current association/profile/role, exact action branches and fresh reviewed source-instance/IMDS control are required; routine metadata does not establish source control')
    return output
