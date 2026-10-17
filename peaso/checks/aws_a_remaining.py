"""Remaining SSM/ASG/Config predicates over existing read-only metadata."""
from . import register,result,unknown
from .facts import get,list_of_objects,Unavailable
from .fixtures import CASES
from .aws_a_facts import complete_items,scope_subject,scope_fixture,api_optional

NATIVE_IDS=[]
SUBJECT={"scope":"123456789012/us-east-1"}


@register("aws.a.ec2.ssm_managed_source","aws","hardening","instance","EC2 instance is registered with Systems Manager, or stopped status is reviewed",
    "medium","CM-8","Review Systems Manager registration; stopped instances remain source owner review.",dependencies=["instance","ssm_managed_instance"])
def ssm_managed(item,index):
    state=get(item,"State.Name",str)
    if state=="stopped":
        return "MANUAL",{"reason":"Pinned source stopped-instance INFO"}
    if state not in {"pending","running","shutting-down","terminated","stopping"}:
        return unknown("unrecognized EC2 state")
    iid=get(item,"InstanceId",str);scope=get(index,"context.scope",str)
    rows=complete_items(index,"ssm_managed_instance",scope)
    identifiers=[get(row,"InstanceId",str) for row in rows]
    return result(iid not in identifiers,registered_instance=iid in identifiers,semantics="Registration metadata only; source does not require online ping status or execute commands")
CASES["aws.a.ec2.ssm_managed_source"]={"pass":{"InstanceId":"i-inert","State":{"Name":"running"}},"fail":{"InstanceId":"i-other","State":{"Name":"running"}},"manual":{"State":{"Name":"stopped"}},"missing":{},"malformed":None,"index":{**scope_fixture("ssm_managed_instance",[{"InstanceId":"i-inert"}]),"context":{"scope":"123456789012/us-east-1"}}}
NATIVE_IDS.append("aws.a.ec2.ssm_managed_source")


@register("aws.a.autoscaling.tag_propagation","aws","hardening","autoscaling_group","Auto Scaling group has no tag with propagation disabled",
    "medium","CM-6","Review tag propagation settings on the group without reading or changing instances.")
def tag_propagation(item,index):
    rows=list_of_objects(get(item,"Tags",list))
    disabled=sum(not get(row,"PropagateAtLaunch",bool) for row in rows)
    return result(bool(disabled),disabled_propagation_tags=disabled)
CASES["aws.a.autoscaling.tag_propagation"]={"pass":{"Tags":[{"PropagateAtLaunch":True}]},"fail":{"Tags":[{"PropagateAtLaunch":False}]},"missing":{},"malformed":None}
NATIVE_IDS.append("aws.a.autoscaling.tag_propagation")


@register("aws.a.config.account_org_aggregators_delegated","aws","hardening","config_account_aggregator_inventory","Account Config aggregators are organizational, cover all regions and have delegated administration",
    "high","CM-8","Review existing organization aggregators and delegated administrator metadata; service enablement is outside collection.",target="scope",dependencies=["config_account_aggregator_inventory","config_delegated_administrator"])
def config_org(item,index):
    scope=scope_subject(item);rows=complete_items(index,"config_account_aggregator_inventory",scope)
    if not rows:
        return result(True,organization_aggregator_count=0,reason="Complete all-enabled-region inventory has no aggregators")
    failed=False
    for row in rows:
        source=api_optional(row,"OrganizationAggregationSource",dict,None,operation="config:DescribeConfigurationAggregators")
        if source is None:
            failed=True
            continue
        if "AllAwsRegions" in source:
            covers=get(source,"AllAwsRegions",bool)
        else:
            if get(row,"_provenance.operation",str)!="config:DescribeConfigurationAggregators" or get(row,"_provenance.native_response_complete",bool) is not True:
                raise Unavailable("organization region-coverage omission not proven")
            covers=False
        if not covers:failed=True
    if failed:
        return result(True,reason="At least one source aggregator is not organizational or does not cover all regions")
    try:
        delegates=complete_items(index,"config_delegated_administrator",scope)
    except Unavailable:
        return "MANUAL",{"reason":"Pinned source complete org/all-regions aggregate requires delegated administrator owner review when lookup unavailable"}
    return result(not bool(delegates),delegated_administrator_count=len(delegates))
AGG={"OrganizationAggregationSource":{"AllAwsRegions":True},"_provenance":{"operation":"config:DescribeConfigurationAggregators","native_response_complete":True}}
GOOD=scope_fixture("config_account_aggregator_inventory",[AGG]);GOOD["collections"].update(scope_fixture("config_delegated_administrator",[{"Id":"123456789012"}])["collections"])
CASES["aws.a.config.account_org_aggregators_delegated"]={"pass":SUBJECT,"fail":SUBJECT,"missing":{},"malformed":None,"index":GOOD,"fail_index":scope_fixture("config_account_aggregator_inventory",[])}
NATIVE_IDS.append("aws.a.config.account_org_aggregators_delegated")
