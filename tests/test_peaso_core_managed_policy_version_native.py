"""Managed default-version identity gates the core IAM policy verdict.

Inert native-shaped records; no cloud SDK, credentials, or network requests.
"""
from copy import deepcopy
import pytest
from peaso.checks import aws_documents, aws_admin

NARROW={'Statement':[{'Effect':'Allow','Action':'s3:GetObject','Resource':'*'}]}
ADMIN={'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}


def managed(document=NARROW):
    return {'DefaultVersionId':'v2','PolicyVersionList':[
        {'VersionId':'v1','IsDefaultVersion':False,'Document':deepcopy(ADMIN)},
        {'VersionId':'v2','IsDefaultVersion':True,'Document':deepcopy(document)}]}


@pytest.mark.parametrize('unsafe',[False,True])
@pytest.mark.parametrize('reverse',[False,True])
def test_only_the_native_selected_default_decides_the_verdict(unsafe,reverse):
    item=managed(ADMIN if unsafe else NARROW)
    if reverse:item['PolicyVersionList'].reverse()
    before=deepcopy(item)
    documents,unresolved=aws_documents(item)
    assert documents==[ADMIN if unsafe else NARROW] and unresolved==0
    assert aws_admin(item,{})[0]==('FAIL' if unsafe else 'PASS')
    assert item==before


@pytest.mark.parametrize('mutation',[
    'missing_default','empty_default','blank_default','nonstring_default',
    'missing_version_id','empty_version_id','blank_version_id','nonstring_version_id',
    'duplicate_version_id','missing_flag','string_flag','integer_flag',
    'no_default_flag','two_default_flags','selected_unflagged','selected_absent',
    'empty_versions','malformed_versions','missing_selected_document',
])
def test_inconsistent_versions_consume_no_document_and_never_pass(mutation):
    item=managed();versions=item['PolicyVersionList']
    if mutation=='missing_default':del item['DefaultVersionId']
    elif mutation=='empty_default':item['DefaultVersionId']=''
    elif mutation=='blank_default':item['DefaultVersionId']=' '
    elif mutation=='nonstring_default':item['DefaultVersionId']=2
    elif mutation=='missing_version_id':del versions[0]['VersionId']
    elif mutation=='empty_version_id':versions[0]['VersionId']=''
    elif mutation=='blank_version_id':versions[0]['VersionId']=' '
    elif mutation=='nonstring_version_id':versions[0]['VersionId']=1
    elif mutation=='duplicate_version_id':versions[0]['VersionId']='v2'
    elif mutation=='missing_flag':del versions[0]['IsDefaultVersion']
    elif mutation=='string_flag':versions[0]['IsDefaultVersion']='false'
    elif mutation=='integer_flag':versions[0]['IsDefaultVersion']=0
    elif mutation=='no_default_flag':versions[1]['IsDefaultVersion']=False
    elif mutation=='two_default_flags':versions[0]['IsDefaultVersion']=True
    elif mutation=='selected_unflagged':
        versions[0]['IsDefaultVersion']=True;versions[1]['IsDefaultVersion']=False
    elif mutation=='selected_absent':item['DefaultVersionId']='v3'
    elif mutation=='empty_versions':item['PolicyVersionList']=[]
    elif mutation=='malformed_versions':item['PolicyVersionList']={}
    elif mutation=='missing_selected_document':del versions[1]['Document']
    else:raise AssertionError(mutation)
    before=deepcopy(item)
    documents,unresolved=aws_documents(item)
    assert documents==[] and unresolved>0
    assert aws_admin(item,{})[0]=='UNKNOWN'
    assert item==before


@pytest.mark.parametrize('key',[None,'UserPolicyList','RolePolicyList','GroupPolicyList'])
@pytest.mark.parametrize('unsafe',[False,True])
def test_direct_and_inline_documents_do_not_require_managed_version_fields(key,unsafe):
    document=deepcopy(ADMIN if unsafe else NARROW)
    item={'PolicyDocument':document} if key is None else {key:[{'PolicyDocument':document}]}
    before=deepcopy(item)
    assert aws_documents(item)==([document],0)
    assert aws_admin(item,{})[0]==('FAIL' if unsafe else 'PASS')
    assert item==before


@pytest.mark.parametrize('unsafe',[False,True])
def test_valid_direct_evidence_is_retained_when_managed_versions_conflict(unsafe):
    item=managed();item['DefaultVersionId']='absent'
    item['PolicyDocument']=deepcopy(ADMIN if unsafe else NARROW)
    documents,unresolved=aws_documents(item)
    assert documents==[item['PolicyDocument']] and unresolved>0
    # A confirmed direct admin grant remains decisive; a narrow direct grant
    # cannot establish safety while other managed evidence is unresolved.
    assert aws_admin(item,{})[0]==('FAIL' if unsafe else 'UNKNOWN')
