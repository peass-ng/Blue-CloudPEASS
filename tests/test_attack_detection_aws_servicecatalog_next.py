"""Synthetic derivatives of five live Service Catalog route shapes.

The live receipts contain temporary S3 URLs and account identifiers and stay
private. These records preserve only CloudTrail fields required by the rules.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
REGION = "us-east-1"
PRODUCT = "prod-abcdefghij"
PORTFOLIO = "port-abcdefghij"
ARTIFACT = "pa-abcdefghij"
RECORD = "rec-abcdefghij"
PROVISIONED = "pp-abcdefghij"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-launch"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-actor/test"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(name, request, response=None, *, actor=ACTOR, minutes=0, read=False):
    return {"eventSource":"servicecatalog.amazonaws.com","eventName":name,
            "eventCategory":"Management","eventType":"AwsApiCall",
            "managementEvent":True,"readOnly":read,
            "recipientAccountId":ACCOUNT,"awsRegion":REGION,
            "eventID":f"11111111-1111-4111-8111-{minutes+1:012d}",
            "eventTime":(BASE+timedelta(minutes=minutes)).isoformat(),
            "userIdentity":{"type":"AssumedRole","accountId":ACCOUNT,"arn":actor},
            "requestParameters":request,"responseElements":response}


CASES = [
    ("CreateConstraint",{"portfolioId":PORTFOLIO,"productId":PRODUCT,"type":"LAUNCH",
                         "parameters":'{"RoleArn":"'+ROLE+'"}'},
     {"constraintDetail":{"type":"LAUNCH","portfolioId":PORTFOLIO,
                          "productId":PRODUCT,"constraintId":"cons-abcdefghij"}},
     "launch_role_constraint",False),
    ("AssociatePrincipalWithPortfolio",{"portfolioId":PORTFOLIO,"principalType":"IAM",
                                        "principalARN":ROLE},None,"principal_granted",False),
    ("AssociatePrincipalWithPortfolio",{"portfolioId":PORTFOLIO,"principalType":"IAM_PATTERN",
                                        "principalARN":"arn:aws:iam:::role/synthetic-*"},None,
     "principal_pattern_granted",False),
    ("GetProvisionedProductOutputs",{"provisionedProductId":PROVISIONED,"pageSize":20},
     None,"outputs_accessed",True),
]


@pytest.mark.parametrize("name,params,response,flag,read",CASES)
def test_servicecatalog_single_event_routes(name,params,response,flag,read):
    row=event(name,params,response,read=read)
    rule=Rule(id="synthetic-"+flag,title="Synthetic Service Catalog",description="Synthetic",
              level="medium",technique_id="synthetic",product="aws",
              selection={"event.source":"servicecatalog.amazonaws.com","event.name":name,
                         "event.outcome":"success","request.servicecatalog_"+flag:True})
    assert len(detect_aws_events([row],[rule]))==1
    for changed in ({"errorCode":"AccessDeniedException"},{"eventSource":"wrong.amazonaws.com"},
                    {"managementEvent":False},{"readOnly":not read},
                    {"userIdentity":{"accountId":"111111111111","arn":ACTOR}}):
        bad=deepcopy(row);bad.update(changed)
        assert detect_aws_events([bad],[rule])==[]
    if name=="CreateConstraint":
        assert detect_aws_events([{**row,"responseElements":None}],[rule])==[]
    if flag=="principal_pattern_granted":
        bad=deepcopy(row);bad["requestParameters"]["principalARN"]=ROLE
        assert detect_aws_events([bad],[rule])==[]


def test_servicecatalog_artifact_provision_correlation():
    created=event("CreateProvisioningArtifact",{"productId":PRODUCT,
                  "parameters":{"name":"synthetic","type":"CLOUD_FORMATION_TEMPLATE",
                                "info":{"LoadTemplateFromURL":"https://example.invalid/synthetic"}}},
                  {"provisioningArtifactDetail":{"id":ARTIFACT}},minutes=1)
    provision=event("ProvisionProduct",{"productId":PRODUCT,"provisioningArtifactId":ARTIFACT,
                    "pathId":"lp-abcdefghij"},
                    {"recordDetail":{"recordId":RECORD,"productId":PRODUCT,
                                     "provisioningArtifactId":ARTIFACT,"status":"IN_PROGRESS"}},minutes=2)
    rule=Rule(id="synthetic-pair",title="Synthetic Service Catalog pair",description="Synthetic",
              level="high",technique_id="synthetic",product="aws",
              selection={"event.source":"servicecatalog.amazonaws.com","event.name":"ProvisionProduct",
                         "event.outcome":"success",
                         "request.servicecatalog_artifact_created_then_provisioned":True})
    assert len(detect_aws_events([created,provision],[rule]))==1
    assert detect_aws_events([provision],[rule])==[]
    for field,value in (("productId","prod-zzzzzzzzzz"),
                        ("provisioningArtifactId","pa-zzzzzzzzzz")):
        bad=deepcopy(provision);bad["requestParameters"][field]=value
        if field=="productId":bad["responseElements"]["recordDetail"][field]=value
        else:bad["responseElements"]["recordDetail"][field]=value
        assert detect_aws_events([created,bad],[rule])==[]
    bad=deepcopy(provision);bad["userIdentity"]["arn"]=f"arn:aws:iam::{ACCOUNT}:user/other"
    assert detect_aws_events([created,bad],[rule])==[]
    bad=deepcopy(provision);bad["eventTime"]=(BASE+timedelta(hours=2)).isoformat()
    assert detect_aws_events([created,bad],[rule])==[]
    bad=deepcopy(provision);bad["errorCode"]="AccessDeniedException"
    assert detect_aws_events([created,bad],[rule])==[]
