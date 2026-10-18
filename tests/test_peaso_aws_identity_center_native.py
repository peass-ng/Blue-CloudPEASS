"""Current SDK joins, completeness and end-to-end Identity Center decisions."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, aws_identity_center_native as native
from peaso.collectors.bulk_evidence import collect
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE=ACCOUNT+'/'+REGION
INSTANCE='arn:aws:sso:::instance/ssoins-1234567890abcdef'
PERMISSION='arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef'
STORE='d-1234567890'
USER='12345678-1234-1234-1234-123456789012'
GROUP='22345678-1234-1234-1234-123456789012'
MEMBERSHIP='32345678-1234-1234-1234-123456789012'
CHECK='aws_identity_center_sso_configured'


def decisions(read):
    snap=make_snapshot('aws',[SCOPE],[{'type':'identity_center','scope':SCOPE,'service':'sso-admin',
                                    'status':read.status,'items':read.items,**({'error':read.error} if read.error else {})}])
    return [r['status'] for r in evaluate_snapshot(snap,checks=[CHECK])['findings']]


def responses(sdk,mode):
    session,add=sdk;admin,store=add('sso-admin'),add('identitystore')
    stubs=(admin,store)
    instance={'InstanceArn':INSTANCE,'IdentityStoreId':STORE,'OwnerAccountId':ACCOUNT,'Status':'ACTIVE'}
    if mode=='foreign_instance':instance['InstanceArn']=INSTANCE.replace('arn:aws:','arn:aws-cn:')
    if mode=='missing_status':instance.pop('Status')
    if mode=='inactive_instance':instance['Status']='CREATE_IN_PROGRESS'
    if mode=='missing_instance_owner':instance.pop('OwnerAccountId')
    if mode=='denied_instances':
        admin.add_client_error('list_instances','AccessDeniedException',http_status_code=403,expected_params={});return session,stubs
    if mode=='truncated_instances':
        admin.add_response('list_instances',{'Instances':[instance],'NextToken':'next'},{});return session,stubs
    admin.add_response('list_instances',{'Instances':[] if mode=='empty_instances' else [instance]* (2 if mode=='duplicate_instance' else 1)}, {})
    if mode in ('empty_instances','foreign_instance','missing_status','inactive_instance','missing_instance_owner'):return session,stubs
    args={'InstanceArn':INSTANCE}
    if mode=='denied_sets':
        admin.add_client_error('list_permission_sets','AccessDeniedException',http_status_code=403,expected_params=args);return session,stubs
    permissions=[] if mode=='empty_sets' else [PERMISSION]
    if mode=='foreign_set':permissions=[PERMISSION.replace('ssoins-1234567890abcdef','ssoins-ffffffffffffffff')]
    if mode=='duplicate_set':permissions*=2
    admin.add_response('list_permission_sets',{'PermissionSets':permissions,**({'NextToken':'next'}if mode=='truncated_sets'else{})},args)
    if mode in ('empty_sets','foreign_set','truncated_sets'):return session,stubs
    group=mode.startswith('group_') or mode=='complete_group'
    assignment={'AccountId':ACCOUNT,'PermissionSetArn':PERMISSION,'PrincipalType':'GROUP' if group else 'USER','PrincipalId':GROUP if group else USER}
    if mode=='foreign_account':assignment['AccountId']='999999999999'
    if mode=='wrong_assignment_set':assignment['PermissionSetArn']=PERMISSION.replace('ps-1234567890abcdef','ps-ffffffffffffffff')
    args={'InstanceArn':INSTANCE,'AccountId':ACCOUNT,'PermissionSetArn':PERMISSION}
    if mode=='denied_assignments':
        admin.add_client_error('list_account_assignments','AccessDeniedException',http_status_code=403,expected_params=args);return session,stubs
    admin.add_response('list_account_assignments',{'AccountAssignments':[] if mode=='empty_assignments' else [assignment]*(2 if mode=='duplicate_assignment' else 1),
                       **({'NextToken':'next'}if mode=='truncated_assignments'else{})},args)
    if mode in ('empty_assignments','foreign_account','wrong_assignment_set','truncated_assignments'):return session,stubs
    if group:
        member={'IdentityStoreId':STORE,'MembershipId':MEMBERSHIP,
                'GroupId':GROUP,'MemberId':{'UserId':USER}}
        if mode=='group_foreign_store':member['IdentityStoreId']='d-ffffffff00'
        if mode=='group_foreign_group':member['GroupId']=USER
        if mode=='group_missing_group':member.pop('GroupId')
        if mode=='group_missing_membership_id':member.pop('MembershipId')
        args={'IdentityStoreId':STORE,'GroupId':GROUP}
        if mode=='group_denied':
            store.add_client_error('list_group_memberships','AccessDeniedException',http_status_code=403,expected_params=args);return session,stubs
        if mode=='group_empty_first_page':
            store.add_response('list_group_memberships',{'GroupMemberships':[],'NextToken':'next'},args)
            args={**args,'NextToken':'next'}
        store.add_response('list_group_memberships',{'GroupMemberships':[] if mode=='group_empty' else [member]*(2 if mode=='group_duplicate' else 1),
                           **({'NextToken':'next'} if mode=='group_truncated' else {})},args)
        if mode in ('group_empty','group_truncated','group_foreign_store','group_foreign_group','group_missing_group','group_missing_membership_id','group_duplicate'):return session,stubs
    user={'IdentityStoreId':STORE,'UserId':USER,
          'UserStatus':'DISABLED' if mode in ('disabled','group_disabled') else 'ENABLED',
          'UserName':'not-exported-private-fixture-name','DisplayName':'not-exported-private-fixture-profile'}
    if mode=='missing_user_status':user.pop('UserStatus')
    if mode=='foreign_user_store':user['IdentityStoreId']='d-ffffffff00'
    if mode=='foreign_user':user['UserId']=GROUP
    args={'IdentityStoreId':STORE,'UserId':USER}
    if mode=='denied_user':store.add_client_error('describe_user','AccessDeniedException',http_status_code=403,expected_params=args)
    else:store.add_response('describe_user',user,args)
    return session,stubs


@pytest.mark.parametrize('mode,expected',[
 ('complete','PASS'),('complete_group','PASS'),('group_empty_first_page','PASS'),
 ('disabled','FAIL'),('group_disabled','FAIL'),('empty_sets','FAIL'),('empty_assignments','FAIL'),('group_empty','FAIL'),
 ('empty_instances','UNKNOWN'),('foreign_instance','UNKNOWN'),('missing_status','UNKNOWN'),('inactive_instance','UNKNOWN'),
 ('missing_instance_owner','UNKNOWN'),('denied_instances','UNKNOWN'),('truncated_instances','UNKNOWN'),
 ('foreign_set','UNKNOWN'),('denied_sets','UNKNOWN'),('truncated_sets','UNKNOWN'),
 ('foreign_account','UNKNOWN'),('wrong_assignment_set','UNKNOWN'),('denied_assignments','UNKNOWN'),('truncated_assignments','UNKNOWN'),
 ('missing_user_status','UNKNOWN'),('foreign_user_store','UNKNOWN'),('foreign_user','UNKNOWN'),('denied_user','UNKNOWN'),
 ('group_denied','UNKNOWN'),('group_truncated','UNKNOWN'),('group_foreign_store','UNKNOWN'),('group_foreign_group','UNKNOWN'),
 ('group_missing_group','UNKNOWN'),('group_missing_membership_id','UNKNOWN'),('group_duplicate','UNKNOWN'),
 ('duplicate_instance','UNKNOWN'),('duplicate_set','UNKNOWN'),('duplicate_assignment','UNKNOWN')])
def test_native_scoped_join_to_real_compliance_decision(sdk,mode,expected):
    session,stubs=responses(sdk,mode)
    read=native.identity_center(aws.Requests({'retry_attempts':1,**({'max_pages':1}if'truncated' in mode else{})}),session,REGION,ACCOUNT)
    if expected=='UNKNOWN':
        assert read.status not in ('collected','empty') and not read.items
        assert not any(status in ('PASS','FAIL','NOT_APPLICABLE')for status in decisions(read))
    else:
        assert read.status=='collected'
        assert decisions(read)==[expected]
        exported=json.dumps(read.items)
        assert 'not-exported-private-fixture' not in exported
        assert all(row['AccountId']==ACCOUNT for instance in read.items[0]['Instances'] for row in instance['AccountAssignments'])
    for stub in stubs:stub.assert_no_pending_responses()


def test_full_collector_pipeline_registers_native_kind_and_keeps_only_safe_metadata(sdk,monkeypatch):
    session,stubs=responses(sdk,'complete_group');_,add=sdk;sts=add('sts')
    sts.add_response('get_caller_identity',{'Account':ACCOUNT,'Arn':f'arn:aws:iam::{ACCOUNT}:user/auditor','UserId':'reviewer'}, {})
    monkeypatch.setattr(aws,'_session',lambda auth,region:(session,'test-pinned'))
    snapshot=collect(aws,{'provider':'aws','scopes':[SCOPE],'options':{'service_concurrency':1,'retry_attempts':1}},['identity_center'])
    assert [r['status']for r in evaluate_snapshot(snapshot,checks=[CHECK])['findings']]==['PASS']
    assert snapshot['metadata']['calls']==6
    assert 'not-exported-private-fixture' not in json.dumps(snapshot)
    for stub in (*stubs,sts):stub.assert_no_pending_responses()


def test_read_operations_are_declared_and_native_type_is_registered():
    assert set(native.SPECS)<=set(aws.SPECS)
    assert native.READ_ACTIONS<=aws.READ_ACTIONS
    assert native.FETCHERS['identity_center'] is aws.FETCHERS['identity_center']
    assert all(op.startswith(('list_','describe_'))for _,op in native.READ_ACTIONS)


@pytest.mark.parametrize('limit,expected',[(None,'PASS'),(2,'UNKNOWN')])
def test_shared_group_and_user_reads_are_cached_and_expansion_obeys_resource_limit(sdk,limit,expected):
    session,add=sdk;admin,store=add('sso-admin'),add('identitystore')
    second=PERMISSION.replace('ps-1234567890abcdef','ps-ffffffffffffffff')
    user2=USER.replace('12345678-','42345678-',1)
    membership2=MEMBERSHIP.replace('32345678-','52345678-',1)
    admin.add_response('list_instances',{'Instances':[{'InstanceArn':INSTANCE,'IdentityStoreId':STORE,'OwnerAccountId':ACCOUNT,'Status':'ACTIVE'}]}, {})
    admin.add_response('list_permission_sets',{'PermissionSets':[PERMISSION,second]}, {'InstanceArn':INSTANCE})
    for permission in (PERMISSION,second):
        admin.add_response('list_account_assignments',{'AccountAssignments':[{'AccountId':ACCOUNT,'PermissionSetArn':permission,'PrincipalType':'GROUP','PrincipalId':GROUP}]},
                           {'InstanceArn':INSTANCE,'AccountId':ACCOUNT,'PermissionSetArn':permission})
    store.add_response('list_group_memberships',{'GroupMemberships':[
        {'IdentityStoreId':STORE,'MembershipId':mid,
         'GroupId':GROUP,'MemberId':{'UserId':uid}} for mid,uid in ((MEMBERSHIP,USER),(membership2,user2))]},
        {'IdentityStoreId':STORE,'GroupId':GROUP})
    for uid in (USER,user2):
        store.add_response('describe_user',{'IdentityStoreId':STORE,'UserId':uid,'UserStatus':'ENABLED'},
                           {'IdentityStoreId':STORE,'UserId':uid})
    requests=aws.Requests({'retry_attempts':1,**({'max_resources':limit} if limit else {})})
    read=native.identity_center(requests,session,REGION,ACCOUNT)
    assert requests.calls==7
    if expected=='PASS':
        assert decisions(read)==['PASS'] and len(read.items[0]['Instances'][0]['AccountAssignments'])==4
    else:
        assert read.status=='not_collected' and read.error['code']=='identity_center_expanded_assignment_limit'
        assert not any(status in ('PASS','FAIL')for status in decisions(read))
    admin.assert_no_pending_responses();store.assert_no_pending_responses()
