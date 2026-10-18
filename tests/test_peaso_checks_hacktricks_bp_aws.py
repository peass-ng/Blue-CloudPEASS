"""HackTricks Cloud Best Practices AWS predicates: semantics beyond the shared fixtures."""
import copy

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS}


def run(cid, item, index=None):
    return REGISTRY[cid].evaluate(item, index or {})


def case(cid, name):
    return copy.deepcopy(CASES[cid][name])


def test_classic_flow_omitted_field_is_the_documented_false_default():
    status, evidence = run("aws.htbp.cognito.identity_pool_classic_flow_disabled", case("aws.htbp.cognito.identity_pool_classic_flow_disabled", "pass"))
    assert status == "PASS" and evidence["allow_classic_flow"] is False
    assert run("aws.htbp.cognito.identity_pool_classic_flow_disabled", {"IdentityPoolId": "x", "Configuration": {"collection_status": "denied"}})[0] == "UNKNOWN"


def test_writable_attributes_default_explicit_and_immutable_signup():
    cid = "aws.htbp.cognito.client_no_writable_authorization_attributes"
    pool = case(cid, "fail")
    del pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"]
    assert run(cid, pool)[0] == "FAIL"  # complete detail + default broad writes
    pool = case(cid, "fail")
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = ["email"]
    assert run(cid, pool)[0] == "PASS"
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = []
    assert run(cid, pool)[0] == "UNKNOWN"  # empty-list API behavior is not established
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = ["custom:plan"]
    assert run(cid, pool)[0] == "FAIL"
    pool = case(cid, "fail")
    pool["Configuration"]["UserPool"]["SchemaAttributes"][1]["Mutable"] = False
    assert run(cid, pool)[0] == "FAIL"  # self-service signup can set immutable role
    pool["Configuration"]["UserPool"]["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] = True
    assert run(cid, pool)[0] == "UNKNOWN"  # federation/provenance unresolved
    del pool["Configuration"]["UserPool"]["AdminCreateUserConfig"]
    assert run(cid, pool)[0] == "UNKNOWN"


def test_writable_attributes_sanitized_live_tools_schema_shape():
    cid = "aws.htbp.cognito.client_no_writable_authorization_attributes"
    pool = case(cid, "fail")
    pool["Configuration"]["UserPool"]["SchemaAttributes"] = [
        {"Name": "email", "Mutable": True},
        {"Name": "custom:plan", "Mutable": True},
        {"Name": "custom:stripe_customer_id", "Mutable": True},
    ]
    del pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"]
    status, evidence = run(cid, pool)
    assert status == "FAIL"
    assert evidence["clients"] == [{"client_id": "c1", "attributes": ["custom:plan"],
                                     "write_attributes_defaulted": True}]


def test_writable_attributes_missing_malformed_and_mixed_coverage():
    cid = "aws.htbp.cognito.client_no_writable_authorization_attributes"
    pool = case(cid, "fail")
    pool["Clients"]["items"][0]["Configuration"] = {"collection_status": "denied"}
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    pool["Clients"] = {"collection_status": "denied", "items": []}
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = ["custom:tenant_id"]
    status, evidence = run(cid, pool)
    assert status == "UNKNOWN" and evidence["coverage_incomplete"] is True  # name absent from schema
    pool = case(cid, "fail")
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = ["custom:role", 123]
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    configuration = pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]
    del configuration["WriteAttributes"]
    configuration["_coverage"] = {"WriteAttributes": {"status": "not_collected"}}
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = ["email"]
    del pool["Configuration"]["UserPool"]["SchemaAttributes"]
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = ["email"]
    pool["Configuration"]["UserPool"]["SchemaAttributes"].append({"Name": 42, "Mutable": True})
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["UserPoolId"] = "eu-west-1_other"
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    del pool["Clients"]["items"][0]["Configuration"]["collection_status"]
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    pool["Clients"]["items"].append({"ClientId": "c2", "Configuration": {"collection_status": "denied"}})
    status, evidence = run(cid, pool)
    assert status == "FAIL" and evidence["coverage_incomplete"] is True
    pool["Clients"]["collection_status"] = "partial"
    assert run(cid, pool)[0] == "FAIL"
    pool["Clients"]["items"][0]["Configuration"]["UserPoolClient"]["WriteAttributes"] = ["email"]
    assert run(cid, pool)[0] == "UNKNOWN"
    pool = case(cid, "fail")
    pool["Clients"] = {"collection_status": "empty", "items": []}
    del pool["Configuration"]["UserPool"]["SchemaAttributes"]
    assert run(cid, pool)[0] == "NOT_APPLICABLE"


def test_ecs_exec_logging_default_and_cluster_mismatch():
    cid = "aws.htbp.ecs.exec_session_logging_not_disabled"
    item = case(cid, "pass")
    del item["Configuration"]["clusters"][0]["configuration"]
    assert run(cid, item) == ("PASS", run(cid, item)[1]) and run(cid, item)[1]["exec_logging"] == "DEFAULT"
    item["Configuration"]["clusters"] = []
    assert run(cid, item)[0] == "UNKNOWN"


def test_ecs_host_mounts_require_a_mounting_container_and_normalize_paths():
    cid = "aws.htbp.ecs.no_sensitive_host_mounts"
    item = case(cid, "fail")
    item["Definition"]["taskDefinition"]["containerDefinitions"][0].pop("mountPoints")
    assert run(cid, item)[0] == "PASS"
    item = case(cid, "fail")
    item["Definition"]["taskDefinition"]["volumes"][0]["host"]["sourcePath"] = "/etc/"
    assert run(cid, item)[0] == "FAIL"
    item["Definition"]["taskDefinition"]["volumes"][0]["host"]["sourcePath"] = "/etc/ssl/certs"
    assert run(cid, item)[0] == "PASS"
    item["Definition"]["taskDefinition"]["volumes"] = [{"name": "v", "efsVolumeConfiguration": {"fileSystemId": "fs-1"}}]
    assert run(cid, item)[0] == "PASS"


def test_glue_dev_endpoint_and_appsync_scope():
    assert run("aws.htbp.glue.dev_endpoint_not_public", {"EndpointName": "dev", "PublicAddress": "", "PrivateAddress": "10.0.0.1"})[0] == "PASS"
    cid = "aws.htbp.appsync.no_api_key_additional_auth"
    assert run(cid, {**case(cid, "fail"), "apiType": "MERGED"})[0] == "NOT_APPLICABLE"
    assert run(cid, {"apiId": "g1", "authenticationType": "AWS_IAM"})[0] == "PASS"


def test_eks_mode_absent_is_unknown_not_legacy_default():
    item = case("aws.htbp.eks.access_entries_authentication", "fail")
    del item["Cluster"]["cluster"]["accessConfig"]["authenticationMode"]
    assert run("aws.htbp.eks.access_entries_authentication", item)[0] == "UNKNOWN"
