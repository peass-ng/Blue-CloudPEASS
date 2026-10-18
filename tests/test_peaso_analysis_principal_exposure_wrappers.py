"""analysis.principal_exposure reads the resource-policy wrappers of OpenSearch, CodeArtifact, SES and Logs."""
import json

import pytest

from peaso.analysis import analyze
from peaso.analysis.iam import policy_documents
from peaso.snapshot import make_snapshot

ACCOUNT = "111122223333"
SCOPE = f"{ACCOUNT}/us-east-1"
PUBLIC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}
EXTERNAL = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                                                    "Action": "*", "Resource": "*"}]}
OWN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                                               "Action": "*", "Resource": "*"}]}


def opensearch(doc):
    return "opensearch_domain", "opensearch", {"DomainName": "d", "Domain": {"DomainStatus": {
        "ARN": f"arn:aws:es:us-east-1:{ACCOUNT}:domain/d", "AccessPolicies": json.dumps(doc)}, "collection_status": "collected"}}


def codeartifact(doc):
    return "codeartifact_repository", "codeartifact", {"name": "r", "arn": f"arn:aws:codeartifact:us-east-1:{ACCOUNT}:repository/d/r",
        "Policy": {"policy": {"resourceArn": "x", "document": json.dumps(doc), "revision": "1"}, "collection_status": "collected"}}


def ses(doc):
    return "ses_email_identity", "sesv2", {"IdentityName": "example.com", "Identity": {"IdentityType": "DOMAIN",
        "Policies": {"send": json.dumps(doc)}, "collection_status": "collected"}}


def logs(doc):
    return "log_resource_policy", "logs", {"policyName": "p", "policyDocument": doc}


BUILDERS = [opensearch, codeartifact, ses, logs]


@pytest.mark.parametrize("build", BUILDERS)
def test_wrapper_documents_are_extracted(build):
    _, _, item = build(PUBLIC)
    docs = list(policy_documents(item))
    assert len(docs) == 1 and docs[0][1]["Statement"][0]["Principal"] == "*"


@pytest.mark.parametrize("build", BUILDERS)
def test_principal_exposure_flags_public_and_external_but_not_own_account(build):
    def verdict(doc):
        kind, service, item = build(doc)
        snapshot = make_snapshot("aws", [SCOPE], [{"type": kind, "scope": SCOPE, "service": service, "status": "collected", "items": [item]}],
                                 created_at="2026-10-10T00:00:00+00:00")
        found = [f for f in analyze(snapshot)["findings"] if f["check_id"] == "analysis.principal_exposure"]
        return found[0]["status"] if found else None
    assert verdict(PUBLIC) == "FAIL"
    assert verdict(EXTERNAL) == "FAIL"
    assert verdict(OWN) is None


def test_ses_policies_map_ignores_non_documents_and_names_each_path():
    item = {"Identity": {"Policies": {"b": json.dumps(OWN), "a": "not json"}}}
    assert [path for path, _ in policy_documents(item)] == ["Identity.Policies.b"]
