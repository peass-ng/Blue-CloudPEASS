"""Account contact separation (Prowler account_maintain_different_contact_details_to_security_billing_and_operations).

Prowler reads the primary contact (GetContactInformation: FullName, PhoneNumber) and the
BILLING, OPERATIONS and SECURITY alternate contacts (Name, EmailAddress, PhoneNumber) and
passes when the four names, the four phone numbers and the three e-mail addresses are all
distinct. Its evaluator puts a missing contact's ``None`` into those sets, so an account
missing one alternate contact can still reach the expected counts; an access-denied primary
contact silently disables the check.

This native requires all four contacts to be present with their fields, and distinct
normalized names and phone numbers across the four and e-mail addresses across the three
alternates. The collector (``aws_facts_gap._contact_details``) stores only presence flags and
distinct-value counts, never the contact values. GovCloud has no Account Management API
for these contacts and is MANUAL, mirroring ``aws.a.account.security_contact_present``.
"""
from __future__ import annotations

from . import result, unknown
from .facts import Unavailable, get
from .claude_aws_a_ec2 import w
from .aws_gap_core import install

NATIVE_IDS = []
LABELS = ("PRIMARY", "BILLING", "OPERATIONS", "SECURITY")


def _contact(present=True):
    return {"collection_status": "collected", "NamePresent": present, "PhonePresent": present}


CONTACTS = {"id": "account-contact-details", "Partition": "aws",
            "Contacts": {"PRIMARY": _contact(), **{label: {**_contact(), "EmailPresent": True} for label in LABELS[1:]}},
            "DistinctNames": 4, "DistinctPhones": 4, "DistinctEmails": 3, "NamesCompared": 4, "PhonesCompared": 4, "EmailsCompared": 3}


@install("aws.gap.account.distinct_primary_billing_operations_security_contacts", "aws_account_contact_details",
    "Primary, billing, operations and security contacts are all registered and distinct", "medium", "IR-4",
    "Register BILLING, OPERATIONS and SECURITY alternate contacts that differ from each other and from the primary contact (name, e-mail, phone).",
    ids=NATIVE_IDS,
    cases={"pass": CONTACTS, "fail": w(CONTACTS, DistinctPhones=3), "manual": w(CONTACTS, Partition="aws-us-gov"), "index": {},
           "variants": [
               ("FAIL", w(CONTACTS, Contacts__OPERATIONS={"collection_status": "empty", "absent": True}, DistinctNames=3, NamesCompared=3,
                          DistinctPhones=3, PhonesCompared=3, DistinctEmails=2, EmailsCompared=2), None),
               ("FAIL", w(CONTACTS, DistinctEmails=2), None),
               ("FAIL", w(CONTACTS, DistinctNames=3), None),
               ("FAIL", w(CONTACTS, Contacts__BILLING={**_contact(), "EmailPresent": False}, EmailsCompared=2, DistinctEmails=2), None),
               # A known duplicate is a failure even when another contact could not be read.
               ("FAIL", w(CONTACTS, Contacts__PRIMARY={"collection_status": "denied"}, NamesCompared=3, DistinctNames=2,
                          PhonesCompared=3, DistinctPhones=3), None),
               ("UNKNOWN", w(CONTACTS, Contacts__PRIMARY={"collection_status": "denied"}, NamesCompared=3, DistinctNames=3,
                             PhonesCompared=3, DistinctPhones=3), None),
               ("UNKNOWN", w(CONTACTS, Contacts__SECURITY={"collection_status": "unknown"}), None),
               ("UNKNOWN", w(CONTACTS, Partition="aws-iso"), None)]})
def distinct_contacts(item, index):
    partition = get(item, "Partition", str)
    if partition == "aws-us-gov":
        return "MANUAL", {"reason": "Account Management contacts are not available in GovCloud; verify contacts manually"}
    if partition not in ("aws", "aws-cn"):
        return unknown("unrecognized AWS partition")
    contacts = get(item, "Contacts", dict)
    failures, unavailable = [], []
    for label in LABELS:
        contact = contacts.get(label)
        if not isinstance(contact, dict):
            raise Unavailable("contact %s not collected" % label)
        status = contact.get("collection_status")
        if status == "empty" and contact.get("absent") is True:
            failures.append("%s contact missing" % label.lower())
            continue
        if status != "collected":
            unavailable.append(label)
            continue
        fields = ("NamePresent", "PhonePresent") + (() if label == "PRIMARY" else ("EmailPresent",))
        for field in fields:
            if get(contact, field, bool) is not True:
                failures.append("%s contact %s missing" % (label.lower(), field[:-7].lower()))
    for distinct, compared in (("DistinctNames", "NamesCompared"), ("DistinctPhones", "PhonesCompared"), ("DistinctEmails", "EmailsCompared")):
        if get(item, distinct, int) < get(item, compared, int):
            failures.append("contacts share a %s" % distinct[8:-1].lower())
    if failures:
        return result(True, failures=sorted(set(failures)))
    if unavailable:
        raise Unavailable("contacts not readable: " + ", ".join(unavailable))
    expected = {"NamesCompared": 4, "PhonesCompared": 4, "EmailsCompared": 3}
    if any(get(item, key, int) != value for key, value in expected.items()):
        raise Unavailable("contact comparison incomplete")
    return result(False, contacts=len(LABELS))
