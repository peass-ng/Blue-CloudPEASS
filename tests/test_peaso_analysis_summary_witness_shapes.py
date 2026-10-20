"""Malformed list membership must not become an observed access declaration."""
from copy import deepcopy
import pytest
from peaso.analysis.finding_clarity import evidence_summary

@pytest.mark.parametrize('cid,field',[('analysis.network_review','rules'),('analysis.grant_review','grants')])
@pytest.mark.parametrize('values',[['not-a-witness'],[None],[False],[{}], [{'native_rule':'not-a-rule'}], [{'native_grant':True}], [{'unrelated':True}]])
def test_malformed_projection_entries_do_not_make_access_claims(cid,field,values):
    finding={'provider':'aws','check_id':cid,'status':'MANUAL','evidence':{field:values}}
    before=deepcopy(finding)
    assert evidence_summary(finding) is None
    assert finding==before

def test_actual_grant_shape_keeps_declared_and_effective_access_distinct():
    g={'native_grant':{'Effect':'Allow','Action':'*','Resource':'*'},'allowed_declaration':True,'severity':'high','broad':True}
    f={'provider':'aws','check_id':'analysis.grant_review','status':'MANUAL','evidence':{'grants':[g]}}
    assert evidence_summary(f)=='The policy allows all actions on all resources. These broad or high-impact grants can widen control; other policies still affect usable access.'
    for patch in [{'allowed_declaration':False},{'broad':False,'severity':'low'}]:
        f['evidence']['grants']=[dict(g,**patch)]
        assert evidence_summary(f) is None

def test_k8s_empty_ingress_rule_requires_its_native_rule_source():
    f={'provider':'k8s','check_id':'analysis.network_review','status':'MANUAL','evidence':{'rules':[{'native_rule':{}}]}}
    assert evidence_summary(f) is None
    f['evidence']['rules'][0]['source']={'resource_type':'networkpolicy','path':'spec.ingress[0]'}
    assert 'endpoint reachability is not established' in evidence_summary(f)

@pytest.mark.parametrize('native',[{'IpProtocol':None},{'IpProtocol':[]},{'allowed':['not-an-entry']},{'properties':{'protocol':None}},{'ports':['not-a-port']}])
def test_malformed_native_protocol_shapes_do_not_become_public_rule_claims(native):
    f={'provider':'aws','check_id':'analysis.network_review','status':'MANUAL','evidence':{'rules':[{'native_rule':native}]}}
    assert evidence_summary(f) is None

@pytest.mark.parametrize('native',[
    {'IpProtocol':'tcp','FromPort':443,'ToPort':443},
    {'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'10.0.0.0/8'}]},
    {'direction':'EGRESS','allowed':[{'IPProtocol':'tcp','ports':['443']}],'sourceRanges':['0.0.0.0/0']},
    {'direction':'INGRESS','sourceTags':['internal'],'allowed':[{'IPProtocol':'tcp','ports':['443']}]},
    {'properties':{'protocol':'Tcp','destinationPortRange':'443','access':'Deny','direction':'Inbound','sourceAddressPrefix':'Internet'}},
    {'properties':{'protocol':'Tcp','destinationPortRange':'443','access':'Allow','direction':'Inbound','sourceAddressPrefix':'10.0.0.0/8'}},
    {'from':[{'ipBlock':{'cidr':'10.0.0.0/8'}}],'ports':[{'port':443}]},
])
def test_ports_and_private_or_denied_sources_never_imply_public_ingress(native):
    f={'check_id':'analysis.network_review','status':'MANUAL','evidence':{'rules':[{'native_rule':native}]}}
    assert evidence_summary(f) is None

def test_gcp_omitted_source_ranges_use_only_the_documented_ingress_default():
    f={'check_id':'analysis.network_review','status':'MANUAL','evidence':{'rules':[{'native_rule':{'direction':'INGRESS','allowed':[{'IPProtocol':'tcp','ports':['443']}]}}]}}
    assert 'Internet-wide sources on TCP/443' in evidence_summary(f)

@pytest.mark.parametrize('start,end',[(None,443),('443',443),(443,None),(100,80),(-1,443),(443,65536),(False,443)])
def test_malformed_aws_tcp_intervals_do_not_make_public_rule_claims(start,end):
    native={'IpProtocol':'tcp','FromPort':start,'ToPort':end,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}
    f={'check_id':'analysis.network_review','status':'MANUAL','evidence':{'rules':[{'native_rule':native}]}}
    assert evidence_summary(f) is None


def test_public_principal_summary_requires_the_declared_allow_grant():
    e={'principals':[{'classification':'public','native_grant':{'Effect':'Allow','Principal':{'AWS':'*'}},'restrictive_conditions':[],'reason':'public'}]}
    f={'provider':'aws','check_id':'analysis.principal_exposure','status':'FAIL','evidence':e}
    assert evidence_summary(f) is None  # No permitted action was recorded.
    f['evidence']['principals'][0]['native_grant']['Action']='s3:GetObject'
    assert 's3:GetObject' in evidence_summary(f)
    assert 'other policies may still block requests' in evidence_summary(f)
    f['evidence']['principals'][0]['native_grant']['Principal']={'AWS':'arn:aws:iam::111122223333:root'}
    assert evidence_summary(f) is None
    f['evidence']['principals'][0]['native_grant']={'Effect':'Deny','Principal':'*'}
    assert evidence_summary(f) is None


def test_public_conditional_principal_does_not_lose_its_constraints():
    f={'check_id':'analysis.principal_exposure','status':'MANUAL','evidence':{'principals':[{'classification':'public','native_grant':{'Effect':'Allow','Principal':'*','Action':'lambda:InvokeFunction','Condition':{'StringEquals':{'AWS:SourceAccount':'111122223333'}}},'reason':'public_conditional','restrictive_conditions':['source-account']} ]}}
    assert 'Recorded conditions restrict this grant' in evidence_summary(f)
    assert 'other policies may still block requests' in evidence_summary(f)


def test_lambda_public_invocation_explains_the_audience_action_and_access_limit():
    grant={'Effect':'Allow','Principal':{'AWS':['*']},'Action':'lambda:InvokeFunction'}
    finding={'provider':'aws','service':'lambda','check_id':'analysis.principal_exposure',
             'status':'FAIL','evidence':{'principals':[{'classification':'public','native_grant':grant}]}}
    before=deepcopy(finding)
    assert evidence_summary(finding)==('Principal “*” (anyone) is allowed to invoke this Lambda function. '
                                      'This may admit unintended callers; other policies may still block requests.')
    assert finding==before
    # Even older observations without the projected condition list retain the
    # native statement's condition in the explanation.
    grant['Condition']={'StringEquals':{'AWS:SourceAccount':'111122223333'}}
    assert 'Recorded conditions restrict this grant' in evidence_summary(finding)
    assert 'may admit unintended callers' not in evidence_summary(finding)


def test_public_actions_are_bounded_and_never_taken_from_a_deny_statement():
    finding={'check_id':'analysis.principal_exposure','evidence':{'principals':[
        {'classification':'public','native_grant':{'Effect':'Allow','Principal':'*','Action':['s3:GetObject','s3:PutObject','s3:DeleteObject']}},
        {'classification':'public','native_grant':{'Effect':'Deny','Principal':'*','Action':'s3:BypassGovernanceRetention'}}]}}
    summary=evidence_summary(finding)
    assert 's3:GetObject, s3:PutObject and 1 other action' in summary
    assert 's3:BypassGovernanceRetention' not in summary


def test_wildcard_conditions_do_not_claim_to_restrict_a_public_grant():
    entry={'classification':'public','native_grant':{'Effect':'Allow','Principal':'*','Action':'lambda:InvokeFunction',
           'Condition':{'StringLike':{'aws:PrincipalArn':'*'}}}}
    finding={'check_id':'analysis.principal_exposure','evidence':{'principals':[entry]}}
    assert 'may admit unintended callers' in evidence_summary(finding)
    limited=deepcopy(entry)
    limited['native_grant']['Condition']={'StringEquals':{'aws:SourceAccount':'111122223333'}}
    finding['evidence']['principals'].append(limited)
    assert 'Only some grants have limiting conditions' in evidence_summary(finding)


def test_oidc_problem_code_requires_matching_native_issuer_and_principal():
    t={'issuer':'token.actions.githubusercontent.com','federated_principal':'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com','problems':[{'code':'no_sub_condition'}]}
    f={'provider':'aws','check_id':'analysis.federated_trust','status':'FAIL','evidence':{'federated_trusts':[t]}}
    assert evidence_summary(f)=='The OIDC trust for token.actions.githubusercontent.com does not restrict which token subjects it accepts. This may admit unintended token holders; other trust and session controls still affect access.'
    t['federated_principal']='arn:aws:iam::111122223333:saml-provider/example'
    assert evidence_summary(f) is None
    t['federated_principal']='arn:aws:iam::111122223333:oidc-provider/different.example'
    assert evidence_summary(f) is None


@pytest.mark.parametrize('bad',[None,False,{},['not-a-problem'],[{'code':'unreviewed_problem'}]])
def test_undemonstrated_oidc_problem_shapes_do_not_invent_a_missing_restriction(bad):
    f={'provider':'aws','check_id':'analysis.federated_trust','status':'FAIL','evidence':{'federated_trusts':[{'issuer':'token.actions.githubusercontent.com','federated_principal':'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com','problems':bad}]}}
    assert evidence_summary(f) is None


def test_native_shape_error_is_explained_without_exposing_an_internal_reason_code():
    f={'provider':'aws','check_id':'analysis.coverage','status':'UNKNOWN','evidence':{'reason':'malformed_native_fact'}}
    assert evidence_summary(f)=='A collected inventory record is malformed, preventing reliable identity or permission analysis.'
