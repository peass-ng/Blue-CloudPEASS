"""Synthetic derivatives of owned Route 53 Profile management events."""

from urllib.parse import quote

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
PROFILE = "rp-synthetic01"
OTHER_PROFILE = "rp-synthetic02"
VPC = "vpc-abcdef01234567890"
ZONE = "arn:aws:route53:::hostedzone/Z9999999999999"
RESOURCE_ASSOC = "rpr-synthetic01"
PROFILE_ASSOC = "rpassoc-synthetic01"
IDS = {
    "aws-route53-profile-created",
    "aws-route53-profile-resource-associated",
    "aws-route53-profile-resource-updated",
    "aws-route53-profile-vpc-associated",
    "aws-route53-profile-resource-disassociated",
    "aws-route53-profile-vpc-disassociated",
    "aws-route53-profile-resource-vpc-linked",
}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 7
    return selected


def event(name, index, request, response):
    return {
        "eventSource": "route53profiles.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T12:{index:02d}:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def resource_detail(status="CREATING", name="SyntheticZone", profile=PROFILE):
    return {"Id": RESOURCE_ASSOC, "Name": name, "OwnerId": ACCOUNT,
            "ProfileId": profile, "ResourceArn": ZONE,
            "ResourceType": "PRIVATE_HOSTED_ZONE", "Status": status}


def profile_detail(status="CREATING", profile=PROFILE, vpc=VPC):
    return {"Id": PROFILE_ASSOC, "Name": "SyntheticVpc", "OwnerId": ACCOUNT,
            "ProfileId": profile, "ResourceId": vpc, "Status": status}


def sample():
    return [
        event("AssociateResourceToProfile", 0,
              {"Name": "SyntheticZone", "ProfileId": PROFILE, "ResourceArn": ZONE},
              {"ProfileResourceAssociation": resource_detail()}),
        event("AssociateProfile", 1,
              {"Name": "SyntheticVpc", "ProfileId": PROFILE, "ResourceId": VPC},
              {"ProfileAssociation": profile_detail()}),
        event("UpdateProfileResourceAssociation", 2,
              {"Name": "RenamedZone", "ProfileResourceAssociationId": RESOURCE_ASSOC},
              {"ProfileResourceAssociation": resource_detail(status="UPDATING", name="RenamedZone")}),
        event("DisassociateResourceFromProfile", 3,
              {"ProfileId": PROFILE, "ResourceArn": quote(ZONE, safe="")},
              {"ProfileResourceAssociation": resource_detail(status="DELETING", name="RenamedZone")}),
        event("DisassociateProfile", 4,
              {"ProfileId": PROFILE, "ResourceId": VPC},
              {"ProfileAssociation": profile_detail(status="DELETING")}),
        event("CreateProfile", 5,
              {"Name": "SyntheticProfile", "ClientToken": "synthetic-token"},
              {"Profile": {"Id": PROFILE, "Name": "SyntheticProfile",
                           "OwnerId": ACCOUNT,
                           "Arn": f"arn:aws:route53profiles:{REGION}:{ACCOUNT}:profile/{PROFILE}",
                           "Status": "COMPLETE"}}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_owned_configuration_sequence_matches_seven_signals():
    findings = hits(sample())
    assert len(findings) == 7
    assert {finding.technique_id for finding in findings} == IDS


def test_failed_changes_do_not_match_or_correlate():
    rows = sample()
    for row in rows:
        row["errorCode"] = "AccessDeniedException"
    assert hits(rows) == []


def test_resource_and_vpc_response_mismatch_fail_closed():
    rows = sample()
    rows[0]["responseElements"]["ProfileResourceAssociation"]["ResourceArn"] = "arn:aws:route53:::hostedzone/ZOTHER"
    rows[1]["responseElements"]["ProfileAssociation"]["ResourceId"] = "vpc-012345abcdef"
    assert not any(f.technique_id in {"aws-route53-profile-resource-associated",
                                     "aws-route53-profile-vpc-associated",
                                     "aws-route53-profile-resource-vpc-linked"} for f in hits(rows))


def test_encoded_disassociation_resource_arn_matches_exact_response():
    rows = sample()
    assert any(f.technique_id == "aws-route53-profile-resource-disassociated" for f in hits(rows))
    rows[3]["requestParameters"]["ResourceArn"] = quote("arn:aws:route53:::hostedzone/ZOTHER", safe="")
    assert not any(f.technique_id == "aws-route53-profile-resource-disassociated" for f in hits(rows))


def test_update_requires_confirmed_name_or_properties():
    rows = sample()
    rows[2]["responseElements"]["ProfileResourceAssociation"]["Name"] = "OldZone"
    assert not any(f.technique_id == "aws-route53-profile-resource-updated" for f in hits(rows))
    rows = sample()
    rows[2]["requestParameters"].pop("Name")
    assert not any(f.technique_id == "aws-route53-profile-resource-updated" for f in hits(rows))


def test_correlation_requires_same_profile_account_and_hour():
    rows = sample()
    rows[1]["requestParameters"]["ProfileId"] = OTHER_PROFILE
    rows[1]["responseElements"]["ProfileAssociation"]["ProfileId"] = OTHER_PROFILE
    assert not any(f.technique_id == "aws-route53-profile-resource-vpc-linked" for f in hits(rows))
    rows = sample()
    rows[1]["eventTime"] = "2026-10-21T13:01:00Z"
    assert not any(f.technique_id == "aws-route53-profile-resource-vpc-linked" for f in hits(rows))
    rows = sample()
    rows[1]["recipientAccountId"] = "888888888888"
    assert not any(f.technique_id == "aws-route53-profile-resource-vpc-linked" for f in hits(rows))


def test_existing_vpc_then_new_resource_also_correlates():
    rows = sample()
    rows[0]["eventTime"] = "2026-10-21T12:05:00Z"
    assert any(f.technique_id == "aws-route53-profile-resource-vpc-linked" for f in hits(rows))


def test_findings_omit_dns_resource_and_names():
    output = str(hits(sample()))
    assert ZONE not in output
    assert "SyntheticZone" not in output
    assert "RenamedZone" not in output
