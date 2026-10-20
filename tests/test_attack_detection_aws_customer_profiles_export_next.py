"""Synthetic derivatives of seven live Customer Profiles export/read events."""
from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_customer_profiles_export_next import normalize

ACCOUNT="999999999999"
DOMAIN="synthetic_domain"
SEGMENT="synthetic_segment"
HEX32="a"*32
HEX64="b"*64
ACTOR=f"arn:aws:iam::{ACCOUNT}:user/synthetic"

CASES=[
 ("CreateSegmentSnapshot",{"DomainName":DOMAIN,"SegmentDefinitionName":SEGMENT,
   "DataFormat":"JSONL","RoleArn":f"arn:aws:iam::{ACCOUNT}:role/synthetic-export",
   "DestinationUri":"s3://synthetic-bucket/snapshot/"},{"SnapshotId":HEX32},False,
  "segment_snapshot_requested"),
 ("GetSegmentSnapshot",{"DomainName":DOMAIN,"SegmentDefinitionName":SEGMENT,
   "SnapshotId":HEX32},None,True,"segment_snapshot_status_read"),
 ("StartUploadJob",{"DomainName":DOMAIN,"JobId":HEX32},None,False,"upload_job_started"),
 ("StopUploadJob",{"DomainName":DOMAIN,"JobId":HEX32},None,False,"upload_job_stopped"),
 ("GetSegmentMembership",{"DomainName":DOMAIN,"SegmentDefinitionName":SEGMENT,
   "ProfileIds":[HEX32]},{"Profiles":"***","Failures":[]},False,
  "segment_membership_accessed"),
 ("CreateSegmentEstimate",{"DomainName":DOMAIN,
   "SegmentQuery":{"Groups":[{"synthetic":"never-export"}],"Include":"ALL"}},
  {"EstimateId":HEX64,"DomainName":DOMAIN},False,"segment_estimate_requested"),
 ("GetSegmentEstimate",{"DomainName":DOMAIN,"EstimateId":HEX64},None,True,
  "segment_estimate_accessed"),
]


@pytest.mark.parametrize("name,params,response,read,flag",CASES)
def test_customer_profiles_export_routes(name,params,response,read,flag):
    row={"eventSource":"profile.amazonaws.com","eventName":name,
         "eventCategory":"Management","eventType":"AwsApiCall",
         "managementEvent":True,"readOnly":read,
         "recipientAccountId":ACCOUNT,"awsRegion":"us-east-1",
         "eventID":"11111111-1111-4111-8111-111111111111",
         "eventTime":"2026-01-01T00:00:00Z",
         "userIdentity":{"accountId":ACCOUNT,"arn":ACTOR},
         "requestParameters":params,"responseElements":response}
    rule=Rule(id="synthetic-"+flag,title="Synthetic Customer Profiles",
              description="Synthetic",level="medium",technique_id="synthetic",
              product="aws",selection={"event.source":"profile.amazonaws.com",
              "event.name":name,"event.outcome":"success",
              "request.customer_profiles_"+flag:True})
    matches=detect_aws_events([row],[rule]);assert len(matches)==1
    projected=normalize(row);assert projected is not None
    rendered=str(projected)
    for secret in (HEX64,"never-export","synthetic-bucket","synthetic-export"):
        assert secret not in rendered
    if name not in {"StartUploadJob","StopUploadJob"}:
        assert HEX32 not in rendered
    for change in ({"errorCode":"AccessDeniedException"},
                   {"eventSource":"wrong.amazonaws.com"},
                   {"readOnly":not read},{"managementEvent":False},
                   {"recipientAccountId":"111111111111"}):
        denied=deepcopy(row);denied.update(change)
        assert detect_aws_events([denied],[rule])==[]
    denied=deepcopy(row);denied["requestParameters"]["DomainName"]="invalid/domain"
    assert detect_aws_events([denied],[rule])==[]
    if name=="CreateSegmentSnapshot":
        denied=deepcopy(row);denied["responseElements"]=None
        assert detect_aws_events([denied],[rule])==[]
    if name=="CreateSegmentEstimate":
        denied=deepcopy(row);denied["responseElements"]=None
        assert detect_aws_events([denied],[rule])==[]
