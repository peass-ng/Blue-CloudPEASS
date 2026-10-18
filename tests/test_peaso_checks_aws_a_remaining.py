"""Final SSM/ASG/Config source truth cases and read-only SDK pagination."""
import copy
import pytest
from peaso.checks import CHECKS,aws_a_remaining as rules
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY={c.id:c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid",rules.NATIVE_IDS)
def test_remaining_real_states_and_purity(cid):
    cases=CASES[cid]
    for state,expected in (("pass","PASS"),("fail","FAIL"),("manual","MANUAL"),("missing","UNKNOWN"),("malformed","UNKNOWN")):
        if state not in cases:continue
        item,index=copy.deepcopy(cases[state]),copy.deepcopy(cases.get(state+"_index",cases.get("index",{})));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==expected
        assert (item,index)==before
    assert REGISTRY[cid].evaluate({"collection_status":"denied"},cases.get("index",{}))[0]=="UNKNOWN"


def test_ssm_membership_not_online_ping_and_stopped_source_info_is_manual():
    check=REGISTRY["aws.a.ec2.ssm_managed_source"];idx={**scope_fixture("ssm_managed_instance",[{"InstanceId":"i-inert","PingStatus":"ConnectionLost"}]),"context":{"scope":"123456789012/us-east-1"}}
    assert check.evaluate({"InstanceId":"i-inert","State":{"Name":"running"}},idx)[0]=="PASS"
    assert check.evaluate({"State":{"Name":"stopped"}}, {})[0]=="MANUAL"


def test_asg_empty_tag_list_passes_and_one_false_among_many_fails():
    check=REGISTRY["aws.a.autoscaling.tag_propagation"]
    assert check.evaluate({"Tags":[]},{})[0]=="PASS"
    assert check.evaluate({"Tags":[{"PropagateAtLaunch":True},{"PropagateAtLaunch":False}]},{})[0]=="FAIL"


def test_config_successful_empty_failure_and_manual_delegate_lookup_are_distinct():
    check=REGISTRY["aws.a.config.account_org_aggregators_delegated"]
    assert check.evaluate(rules.SUBJECT,scope_fixture(check.kind,[]))[0]=="FAIL"
    assert check.evaluate(rules.SUBJECT,scope_fixture(check.kind,[],status="denied"))[0]=="UNKNOWN"
    idx=copy.deepcopy(rules.GOOD);idx["collections"]["config_delegated_administrator"][0].update(status="denied",items=[])
    assert check.evaluate(rules.SUBJECT,idx)[0]=="MANUAL"
    idx["collections"][check.kind][0]["items"][0]["OrganizationAggregationSource"]={"AwsRegions":["us-east-1"]}
    assert check.evaluate(rules.SUBJECT,idx)[0]=="FAIL"


def test_new_existing_only_metadata_operations_pagination_and_no_enablement(monkeypatch):
    boto3=pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session=boto3.Session(aws_access_key_id="inert",aws_secret_access_key="inert",region_name="us-east-1")
    clients={svc:session.client(svc,region_name="us-east-1") for svc in ("ssm","config","autoscaling","logs","dlm")};stubs={k:Stubber(v) for k,v in clients.items()}
    monkeypatch.setattr(aws.Requests,"client",lambda self,ctx,svc,region:clients[svc])
    stubs["ssm"].add_response("describe_instance_information",{"InstanceInformationList":[],"NextToken":"next"},{})
    stubs["ssm"].add_response("describe_instance_information",{"InstanceInformationList":[]},{"NextToken":"next"})
    stubs["config"].add_response("describe_configuration_aggregators",{"ConfigurationAggregators":[]},{})
    stubs["config"].add_response("describe_aggregation_authorizations",{"AggregationAuthorizations":[]},{})
    stubs["autoscaling"].add_response("describe_auto_scaling_groups",{"AutoScalingGroups":[]},{})
    stubs["logs"].add_response("describe_resource_policies",{"resourcePolicies":[]},{})
    stubs["dlm"].add_response("get_lifecycle_policies",{"Policies":[]},{})
    for stub in stubs.values():stub.activate()
    try:
        requests=aws.Requests({})
        for kind in ("ssm_managed_instance","config_aggregator","config_aggregate_authorization","autoscaling_group","log_resource_policy","dlm_policy"):
            service,operation,expr=aws.SPECS[kind]
            assert requests.pages(session,service,"us-east-1",operation,expr).status=="empty"
        assert requests.calls==7
        assert all(not operation.startswith(("put_","create_","start_","enable_","register_")) for service,operation in aws.READ_ACTIONS)
        for stub in stubs.values():stub.assert_no_pending_responses()
    finally:
        for stub in stubs.values():stub.deactivate()
