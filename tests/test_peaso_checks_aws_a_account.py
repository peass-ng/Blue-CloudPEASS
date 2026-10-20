"""Owner-review questions remain separate from automated security predicates."""
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS, aws_a_account

@pytest.mark.parametrize("cid", aws_a_account.MANUAL_SOURCE_IDS)
def test_manual_owner_review_retains_exact_question_and_provenance(cid):
    root = Path(__file__).resolve().parents[1]
    reviews = json.loads((root / "peaso/rulepacks/reviewed_aws_a_account.json").read_text())
    rows = {r["check_id"]: r for r in json.loads((root / "peaso/rulepacks/upstream_manifest.json").read_text())["checks"]}
    review, source = reviews[cid], rows[cid]
    assert review["disposition"] == "rejected"
    assert review["review_classification"] == "manual_attestation"
    assert review["native_checks"] == []
    assert review["manual_requirement"]["question"] == source["title"]
    reviewed_source=review["reviewed_source"]
    # The refreshed upstream snapshot retains these exact reviewed evaluators.
    # Admit only this observed revision transition, with source path and digest
    # equality still required; an arbitrary future revision remains unreviewed.
    if reviewed_source["revision"] != source["revision"]:
        assert (reviewed_source["revision"],source["revision"]) == (
            "61d2cc55c4539a6b48a3cf9f3729d8f2af300882",
            "7f9eb2cb11ea931f54acccb6e49152358ccf949d")
    assert reviewed_source["repository"] == source["repository"]
    assert reviewed_source["source"].replace(
        "/blob/"+reviewed_source["revision"]+"/", "/blob/"+source["revision"]+"/") == source["source"]
    assert review["reviewed_source"]["evaluator_sha256"] == source["upstream_evaluator"]["sha256"]
    assert {c.id for c in CHECKS if c.id.startswith("aws.a.account.")} <= set(aws_a_account.NATIVE_IDS)


@pytest.mark.parametrize("cid", aws_a_account.NATIVE_IDS)
def test_api_presence_sources_have_real_states_and_keep_denial_unknown(cid):
    import copy
    from peaso.checks.fixtures import CASES
    check = next(c for c in CHECKS if c.id == cid)
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(CASES[cid][state]);before = copy.deepcopy(item)
        assert check.evaluate(item, {})[0] == expected
        assert item == before
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"


def test_govcloud_security_contact_is_source_manual_not_absence_failure():
    check = next(c for c in CHECKS if c.id == "aws.a.account.security_contact_present")
    assert check.evaluate({"Partition": "aws-us-gov"}, {})[0] == "MANUAL"
    assert check.evaluate({"Partition": "aws", "SecurityContact": {"collection_status": "denied"}}, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("known_absent", [False, True])
def test_account_configuration_sdk_absence_and_private_contact_projection(monkeypatch, known_absent):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    from peaso.collectors import aws
    session = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    clients = {service: session.client(service, region_name="us-east-1") for service in ("account", "organizations")}
    monkeypatch.setattr(aws.Requests, "client", lambda self, context, service, region: clients[service])
    contact, organization = Stubber(clients["account"]), Stubber(clients["organizations"])
    if known_absent:
        contact.add_client_error("get_alternate_contact", "ResourceNotFoundException", expected_params={"AlternateContactType": "SECURITY"})
        organization.add_client_error("describe_organization", "AWSOrganizationsNotInUseException", expected_params={})
    else:
        contact.add_response("get_alternate_contact", {"AlternateContact": {"Name": "INERT_PRIVATE_CONTACT_NAME", "EmailAddress": "private@example.invalid", "PhoneNumber": "+10000000000", "Title": "security", "AlternateContactType": "SECURITY"}}, {"AlternateContactType": "SECURITY"})
        organization.add_response("describe_organization", {"Organization": {"Id": "o-inert12345", "Arn": "arn:aws:organizations::123456789012:organization/o-inert12345", "FeatureSet": "ALL", "MasterAccountId": "123456789012", "MasterAccountArn": "arn:aws:organizations::123456789012:account/o-inert12345/123456789012", "MasterAccountEmail": "private@example.invalid"}}, {})
    with contact, organization:
        requests = aws.Requests({})
        read = aws._account_configuration(requests, session, "us-east-1", {"Arn": "arn:aws:iam::123456789012:user/reviewer"})
        assert read.status == "collected" and requests.calls == 2
        serialized = json.dumps(read.items)
        assert "INERT_PRIVATE_CONTACT_NAME" not in serialized and "private@example.invalid" not in serialized
        for cid in aws_a_account.NATIVE_IDS:
            check = next(c for c in CHECKS if c.id == cid)
            assert check.evaluate(read.items[0], {})[0] == ("FAIL" if known_absent else "PASS")
        contact.assert_no_pending_responses();organization.assert_no_pending_responses()
