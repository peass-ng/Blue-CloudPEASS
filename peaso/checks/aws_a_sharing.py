"""Conditional owner-review queries preserve INFO as MANUAL, not invented FAIL."""
from . import register,result,unknown,statements
from .facts import get,list_of_objects,Unavailable
from .fixtures import CASES
from .aws_a_facts import complete_items,scope_subject,scope_fixture
from .claude_aws_a_common import turbot_public_statements

NATIVE_IDS=[]
TRUSTED="123456781234"
TRUST_INDEX={"context":{"metadata":{"trusted_scope_ids":[TRUSTED]}}}


def trusted_accounts(index):
    values=get(index,"context.metadata.trusted_scope_ids",list)
    if any(not isinstance(value,str) or len(value)!=12 or not value.isdigit() for value in values):
        raise Unavailable("malformed configured trusted account list")
    return set(values)


@register("aws.a.config.aggregate_authorization_review","aws","exposure","config_aggregate_authorization","Config aggregation authorization targets a configured trusted account",
    "medium","AC-3","Attest aggregation authorization against the explicitly configured trusted account list.")
def config_authorization(item,index):
    account=get(item,"AuthorizedAccountId")
    if account is None:
        return result(False,authorized_account="null")
    if not isinstance(account,str) or len(account)!=12 or not account.isdigit():
        return unknown("malformed authorized account ID")
    if account in trusted_accounts(index):
        return result(False,authorized_account_trusted=True)
    return "MANUAL",{"reason":"Pinned source INFO: aggregation authorization targets an account outside the configured trusted list"}
CASES["aws.a.config.aggregate_authorization_review"]={"pass":{"AuthorizedAccountId":TRUSTED},"manual":{"AuthorizedAccountId":"210987654321"},"missing":{},"malformed":None,"index":TRUST_INDEX}
NATIVE_IDS.append("aws.a.config.aggregate_authorization_review")


@register("aws.a.dlm.snapshot_sharing_review","aws","exposure","dlm_policy","DLM snapshot sharing targets configured trusted accounts",
    "medium","AC-3","Review active snapshot-management policy sharing against the configured trusted account list.")
def dlm_sharing(item,index):
    policy=get(item,"Details.Policy",dict)
    state=get(policy,"State",str)
    details=get(policy,"PolicyDetails",dict)
    if get(details,"PolicyType",str)!="EBS_SNAPSHOT_MANAGEMENT":
        return "NOT_APPLICABLE",{"reason":"Pinned source snapshot-management-only filter"}
    if state=="DISABLED":
        return "NOT_APPLICABLE",{"reason":"Pinned source disabled-policy skip"}
    if state not in {"ENABLED","ERROR"}:
        return unknown("unrecognized DLM state")
    if "Schedules" not in details:
        if get(item,"Details.collection_status",str)!="collected" or not get(policy,"PolicyId",str):
            raise Unavailable("DLM schedule omission not proven")
        schedules=[]
    else:
        schedules=list_of_objects(get(details,"Schedules",list))
    if len(schedules)>4:
        return unknown("native DLM schedule limit exceeded")
    untrusted=set()
    for schedule in schedules:
        # ShareRules is a documented optional field, and the complete Details
        # response's PolicyId proves SDK metadata provenance for an omission.
        if "ShareRules" not in schedule:
            if get(item,"Details.collection_status",str)!="collected" or not get(policy,"PolicyId",str):
                raise Unavailable("DLM sharing omission not proven")
            continue
        shares=list_of_objects(get(schedule,"ShareRules",list))
        if len(shares)>1:
            return unknown("native DLM ShareRules limit exceeded")
        if shares:
            targets=get(shares[0],"TargetAccounts",list)
            if any(not isinstance(value,str) or len(value)!=12 or not value.isdigit() for value in targets):
                return unknown("malformed sharing target accounts")
            if targets:untrusted.update(set(targets)-trusted_accounts(index))
    if untrusted:
        return "MANUAL",{"reason":"Pinned source INFO: snapshot-sharing targets require owner review","untrusted_target_count":len(untrusted)}
    return result(False,untrusted_target_count=0)
DLM={"Details":{"collection_status":"collected","Policy":{"PolicyId":"policy-inert","State":"ENABLED","PolicyDetails":{"PolicyType":"EBS_SNAPSHOT_MANAGEMENT","Schedules":[{"ShareRules":[{"TargetAccounts":[TRUSTED]}]}]}}}}
DLM_MANUAL={"Details":{"collection_status":"collected","Policy":{"PolicyId":"policy-inert","State":"ENABLED","PolicyDetails":{"PolicyType":"EBS_SNAPSHOT_MANAGEMENT","Schedules":[{"ShareRules":[{"TargetAccounts":["210987654321"]}]}]}}}}
CASES["aws.a.dlm.snapshot_sharing_review"]={"pass":DLM,"manual":DLM_MANUAL,"missing":{},"malformed":None,"index":TRUST_INDEX}
NATIVE_IDS.append("aws.a.dlm.snapshot_sharing_review")


@register("aws.a.cloudwatch.cross_account_sharing_review","aws","exposure","aws_account","CloudWatch named cross-account sharing role is reviewed",
    "medium","AC-3","Attest declared CloudWatch cross-account sharing role statements when present.",target="scope",dependencies=["iam_role"])
def cloudwatch_sharing(item,index):
    roles=complete_items(index,"iam_role",scope_subject(item))
    for role in roles:
        if get(role,"RoleName",str)=="CloudWatch-CrossAccountSharingRole" and statements(get(role,"AssumeRolePolicyDocument")):
            return "MANUAL",{"reason":"Pinned source INFO: named CloudWatch sharing role has trust statements"}
    return result(False,sharing_statements_present=False)
CASES["aws.a.cloudwatch.cross_account_sharing_review"]={"pass":{"scope":"123456789012/us-east-1"},"manual":{"scope":"123456789012/us-east-1"},"missing":{},"malformed":None,"index":scope_fixture("iam_role",[]),"manual_index":scope_fixture("iam_role",[{"RoleName":"CloudWatch-CrossAccountSharingRole","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Principal":{"AWS":TRUSTED},"Action":"sts:AssumeRole"}]}}])}
NATIVE_IDS.append("aws.a.cloudwatch.cross_account_sharing_review")


@register("aws.a.cloudwatch.resource_policy_declared_public","aws","exposure","log_resource_policy","CloudWatch resource policy avoids the source's unrestricted wildcard principal",
    "high","AC-3","Review declared principals and restrictive source conditions separately from service-side effective authorization.")
def log_policy(item,index):
    document=get(item,"policyDocument")
    if document is None:
        return "MANUAL",{"reason":"Pinned source INFO: policy is explicitly NULL"}
    rows=statements(document)
    return result(bool(turbot_public_statements(rows,arn_equals_wildcard=True)),semantics="Exact declared wildcard/condition-key lint; no effective endpoint or anonymous-access claim")
LOG_GOOD={"policyDocument":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"logs:PutLogEvents","Resource":"*","Condition":{"StringEquals":{"aws:SourceAccount":TRUSTED}}}]}}
LOG_BAD={"policyDocument":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"logs:PutLogEvents","Resource":"*"}]}}
CASES["aws.a.cloudwatch.resource_policy_declared_public"]={"pass":LOG_GOOD,"fail":LOG_BAD,"manual":{"policyDocument":None},"missing":{},"malformed":None}
NATIVE_IDS.append("aws.a.cloudwatch.resource_policy_declared_public")
