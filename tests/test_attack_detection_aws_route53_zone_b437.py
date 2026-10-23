"""Synthetic derivatives of owned Route 53 DNS and VPC association events."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
ZONE = "ZSYNTHETIC"
VPC = "vpc-0123456789abcdef0"
RECORD = "service.synthetic.invalid."
FLAGS = {
    "CREATE": ("aws-route53-dns-record-create", "request.route53_dns_create_observed"),
    "UPSERT": ("aws-route53-dns-record-upsert", "request.route53_dns_upsert_observed"),
    "DELETE": ("aws-route53-dns-record-delete", "request.route53_dns_delete_observed"),
    "AUTH": ("aws-route53-vpc-association-authorized", "request.route53_vpc_association_authorized"),
    "ASSOC": ("aws-route53-vpc-associated", "request.route53_vpc_associated"),
}
RULES = [
    Rule(id=kind, title=kind, description="synthetic", level="low", product="aws",
         technique_id=technique,
         selection={"event.source": "route53.amazonaws.com",
                    "event.name": ("ChangeResourceRecordSets" if kind in {"CREATE", "UPSERT", "DELETE"}
                                   else "CreateVPCAssociationAuthorization" if kind == "AUTH"
                                   else "AssociateVPCWithHostedZone"),
                    "event.outcome": "success", fact: True})
    for kind, (technique, fact) in FLAGS.items()
]


def event(kind):
    name = ("ChangeResourceRecordSets" if kind in {"CREATE", "UPSERT", "DELETE"}
            else "CreateVPCAssociationAuthorization" if kind == "AUTH"
            else "AssociateVPCWithHostedZone")
    request = {"hostedZoneId": ZONE}
    if kind in {"CREATE", "UPSERT", "DELETE"}:
        request["changeBatch"] = {"changes": [{"action": kind,
            "resourceRecordSet": {"name": RECORD, "type": "A", "tTL": 60,
                                  "resourceRecords": [{"value": "192.0.2.99"}]}}]}
    else:
        request["vPC"] = {"vPCId": VPC, "vPCRegion": "us-east-1"}
    return {"eventSource": "route53.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "eventID": "88888888-8888-4888-8888-" + str(list(FLAGS).index(kind)).zfill(12),
            "recipientAccountId": ACCOUNT,
            "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"},
            "requestParameters": request, "responseElements": {}}


def test_five_accepted_routes_and_no_raw_zone_record_or_vpc():
    matches = detect_aws_events([event(kind) for kind in FLAGS], RULES)
    assert len(matches) == 5
    assert {match.technique_id for match in matches} == {item[0] for item in FLAGS.values()}
    assert all(value not in str(matches) for value in (ZONE, VPC, RECORD))


def test_denied_malformed_and_non_dns_record_cases_do_not_match():
    cases = []
    for kind in FLAGS:
        denied = event(kind)
        denied["errorCode"] = "AccessDenied"
        cases.append(denied)
    bad_type = event("UPSERT")
    bad_type["requestParameters"]["changeBatch"]["changes"][0]["resourceRecordSet"]["type"] = "SOA"
    cases.append(bad_type)
    missing_vpc = event("AUTH")
    del missing_vpc["requestParameters"]["vPC"]
    cases.append(missing_vpc)
    read_only = deepcopy(event("ASSOC"))
    read_only["readOnly"] = True
    cases.append(read_only)
    assert detect_aws_events(cases, RULES) == []
