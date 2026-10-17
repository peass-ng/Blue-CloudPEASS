"""Reviewed account presence predicates and separate manual attestation sources.

The lead preserves exact questions, source revisions and framework mappings in
its separate manual catalog. Actual native API presence rules stay distinct.
"""
MANUAL_SOURCE_IDS = (
    "prowler.aws.account_maintain_current_contact_details",
    "prowler.aws.account_security_contact_information_is_registered",
    "prowler.aws.account_security_questions_are_registered_in_the_aws_account",
)

from . import register, result, unknown
from .facts import get
from .fixtures import CASES

NATIVE_IDS = []


@register("aws.a.account.security_contact_present", "aws", "hardening", "aws_account_configuration", "AWS account has a security alternate contact registered",
    "medium", "IR-4", "Register an approved security alternate contact; GovCloud requires manual verification under this source.")
def security_contact(item, index):
    partition = get(item, "Partition", str)
    if partition == "aws-us-gov":
        return "MANUAL", {"reason": "Pinned source GovCloud applicability"}
    if partition not in {"aws", "aws-cn"}:
        return unknown("unrecognized source AWS partition")
    contact = get(item, "SecurityContact", dict)
    if contact.get("collection_status") == "empty" and contact.get("absent") is True:
        return result(True, security_contact_present=False)
    return result(not get(contact, "NamePresent", bool), security_contact_present=get(contact, "NamePresent", bool))
CASES["aws.a.account.security_contact_present"] = {"pass": {"Partition": "aws", "SecurityContact": {"NamePresent": True}},
    "fail": {"Partition": "aws", "SecurityContact": {"collection_status": "empty", "absent": True}}, "missing": {}, "malformed": None,
    "manual": {"Partition": "aws-us-gov"}}
NATIVE_IDS.append("aws.a.account.security_contact_present")


@register("aws.a.account.organization_member", "aws", "hardening", "aws_account_configuration", "AWS account has an Organizations organization ID",
    "medium", "CM-8", "Review membership and intended organizational governance separately from membership presence.")
def organization_member(item, index):
    organization = get(item, "Organization", dict)
    if organization.get("collection_status") == "empty" and organization.get("absent") is True:
        return result(True, organization_member=False)
    value = get(organization, "OrganizationId", str)
    if not value.startswith("o-"):
        return unknown("malformed organization ID")
    return result(False, organization_member=True)
CASES["aws.a.account.organization_member"] = {"pass": {"Organization": {"OrganizationId": "o-inert12345"}},
    "fail": {"Organization": {"collection_status": "empty", "absent": True}}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.account.organization_member")
