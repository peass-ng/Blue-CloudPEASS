"""HackTricks Cloud Best Practices GCP predicates: semantics beyond the shared fixtures."""
import copy

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS}


def run(cid, item, index=None):
    return REGISTRY[cid].evaluate(item, index or {})


def case(cid, name):
    return copy.deepcopy(CASES[cid][name])


def test_cloud_run_identity_default_and_functions_backing_service():
    cid = "gcp.htbp.cloudrun.service_no_default_compute_sa"
    item = case(cid, "pass")
    item["template"] = {}
    assert run(cid, item)[0] == "FAIL"  # empty serviceAccount = Compute Engine default
    item["labels"] = {"goog-managed-by": "cloudfunctions"}
    assert run(cid, item)[0] == "NOT_APPLICABLE"
    job = case("gcp.htbp.cloudrun.job_no_default_compute_sa", "fail")
    job["template"]["template"]["serviceAccount"] = "batch@p.iam.gserviceaccount.com"
    assert run("gcp.htbp.cloudrun.job_no_default_compute_sa", job)[0] == "PASS"


def test_cloud_run_env_names_heuristic():
    cid = "gcp.htbp.cloudrun.job_secret_env_from_secret_manager"
    item = case(cid, "fail")
    env = item["template"]["template"]["containers"][0]["env"]
    env[:] = [{"name": "STRIPE_API_KEY"}]
    assert run(cid, item)[0] == "FAIL"
    env[:] = [{"name": "API_KEY_SECRET_NAME"}, {"name": "PORT"}]
    assert run(cid, item)[0] == "PASS"
    del item["template"]["template"]["containers"][0]["env"]
    assert run(cid, item)[0] == "PASS"


def test_function_generation_defaults():
    cid = "gcp.htbp.function.runtime_no_default_sa"
    assert run(cid, {**case(cid, "pass"), "serviceConfig": {}})[0] == "FAIL"
    assert run(cid, {**case(cid, "pass"), "environment": "GEN_3"})[0] == "UNKNOWN"
    assert run(cid, {**case(cid, "pass"), "serviceConfig": {"serviceAccountEmail": "1-compute@developer.gserviceaccount.com"}})[0] == "FAIL"


def test_appengine_absent_service_account_is_default():
    assert run("gcp.htbp.appengine.no_default_service_account", {"name": "apps/p", "id": "p"})[0] == "FAIL"


def test_template_scope_and_representation():
    cid = "gcp.htbp.instance_template.no_default_sa_full_scope"
    item = case(cid, "fail")
    item["properties"]["serviceAccounts"][0]["scopes"] = ["https://www.googleapis.com/auth/devstorage.read_only"]
    assert run(cid, item)[0] == "PASS"
    assert run(cid, {**case(cid, "pass"), "properties": {}})[0] == "PASS"  # full representation, no identity
    assert run(cid, {"name": "t", "properties": {}})[0] == "UNKNOWN"  # partial representation


def test_kubelet_defaults_inheritance():
    cid = "gcp.htbp.gke.kubelet_readonly_port_disabled"
    defaults = {"nodePoolDefaults": {"nodeConfigDefaults": {"nodeKubeletConfig": {"insecureKubeletReadonlyPortEnabled": False}}}}
    assert run(cid, {"name": "c", **defaults, "nodePools": [{"name": "p", "config": {}}]})[0] == "PASS"
    assert run(cid, {"name": "c", "nodePoolAutoConfig": {"nodeKubeletConfig": {"insecureKubeletReadonlyPortEnabled": True}}})[0] == "FAIL"
    assert run(cid, {"name": "c", "nodePoolAutoConfig": {"nodeKubeletConfig": {"insecureKubeletReadonlyPortEnabled": False}}})[0] == "PASS"
    assert run(cid, {"name": "c"})[0] == "MANUAL"


def test_default_sink_scope_and_kms_window():
    assert run("gcp.htbp.logging.default_sink_not_disabled", {"name": "projects/p/sinks/audit", "disabled": True})[0] == "NOT_APPLICABLE"
    cid = "gcp.htbp.kms.destroy_window_not_shortened"
    assert run(cid, {**case(cid, "fail"), "destroyScheduledDuration": "604800s"})[0] == "PASS"
    assert run(cid, {"name": "k"})[0] == "UNKNOWN"  # omission is only the 30d default on a full representation


def test_default_object_acl_ubla_and_authenticated_users():
    cid = "gcp.htbp.storage.default_object_acl_not_public"
    item = case(cid, "fail")
    item["iamConfiguration"]["uniformBucketLevelAccess"]["enabled"] = True
    assert run(cid, item)[0] == "NOT_APPLICABLE"
    item = case(cid, "fail")
    item["defaultObjectAcl"] = [{"entity": "allAuthenticatedUsers", "role": "READER"}]
    assert run(cid, item)[0] == "FAIL"


def test_push_endpoint_hosts():
    cid = "gcp.htbp.pubsub.push_endpoint_not_tunnel"
    base = case(cid, "pass")
    for endpoint, status in (("https://203.0.113.7/x", "FAIL"), ("https://[2001:db8::1]/x", "FAIL"), ("https://x.webhook.site/", "FAIL"),
                             ("https://api.example.com/push", "PASS"), ("https://notngrok.io.example.com/", "PASS")):
        assert run(cid, {**base, "pushConfig": {"pushEndpoint": endpoint}})[0] == status, endpoint
    assert run(cid, {**base, "pushConfig": {}})[0] == "NOT_APPLICABLE"


def test_virtual_repo_precedence_requires_inventory():
    cid = "gcp.htbp.artifactregistry.virtual_repo_private_precedence"
    index = copy.deepcopy(CASES[cid]["index"])
    assert run(cid, case(cid, "fail"), {})[0] == "UNKNOWN"
    index["artifact_repository"] = index["artifact_repository"][:1]
    assert run(cid, case(cid, "pass"), index)[0] == "UNKNOWN"  # upstream not inventoried
    assert run(cid, {"name": "r", "mode": "STANDARD_REPOSITORY"}, index)[0] == "NOT_APPLICABLE"


def test_function_env_names_require_collector_marker_and_skip_pointer_names():
    cid = "gcp.htbp.function.secret_env_from_secret_manager"
    item = case(cid, "fail")
    item["serviceConfig"]["environmentVariableNames"] = ["API_KEY_SECRET_NAME", "PORT"]
    assert run(cid, item)[0] == "PASS"
    item["serviceConfig"]["environmentVariableNames"] = []
    assert run(cid, item)[0] == "PASS"


def test_collected_function_flows_into_env_check():
    from peaso.collectors import gcp
    from tests.test_peaso_collectors_gcp import collection, snapshot
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": []}
        return {"functions": [{"name": "projects/p-one/locations/r/functions/a", "serviceConfig": {"environmentVariables": {"DB_PASSWORD": "v"}}},
                              {"name": "projects/p-one/locations/r/functions/b", "serviceConfig": {"serviceAccountEmail": "x@p-one.iam.gserviceaccount.com"}}]}
    result, _ = snapshot(["function"], resolve)
    items = {x["name"].rsplit("/", 1)[1]: x for x in collection(result, "function")["items"]}
    cid = "gcp.htbp.function.secret_env_from_secret_manager"
    assert run(cid, items["a"])[0] == "FAIL" and run(cid, items["b"])[0] == "PASS"
    assert gcp.sanitize({"environmentVariables": {"A": "v"}}) == {"environmentVariableNames": ["A"]}


def test_cloudbuild_pr_gate_semantics():
    cid = "gcp.htbp.cloudbuild.pr_trigger_gated"
    item = case(cid, "fail")
    item["approvalConfig"] = {"approvalRequired": True}
    assert run(cid, item)[0] == "PASS"
    item = case(cid, "fail")
    item["github"]["pullRequest"]["commentControl"] = "COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY"
    assert run(cid, item)[0] == "PASS"
    item = case(cid, "fail")
    item["disabled"] = True
    assert run(cid, item)[0] == "NOT_APPLICABLE"
    item = case(cid, "fail")
    del item["github"]
    item["repositoryEventConfig"] = {"repository": "projects/p/locations/r/connections/c/repositories/x", "pullRequest": {"branch": ".*"}}
    assert run(cid, item)[0] == "FAIL"


def test_cloudbuild_default_identities():
    cid = "gcp.htbp.cloudbuild.trigger_no_default_sa"
    item = case(cid, "pass")
    del item["serviceAccount"]
    assert run(cid, item)[0] == "FAIL"  # full representation: unset = project default build identity
    item["serviceAccount"] = "projects/p/serviceAccounts/123@cloudbuild.gserviceaccount.com"
    assert run(cid, item)[0] == "FAIL"


def test_hmac_default_sa_and_missing_capture_time():
    cid = "gcp.htbp.storage.hmac_key_not_stale_or_default_sa"
    item = case(cid, "pass")
    item["serviceAccountEmail"] = "123-compute@developer.gserviceaccount.com"
    assert run(cid, item)[0] == "FAIL"
    item = case(cid, "pass")
    del item["_provenance"]
    assert run(cid, item)[0] == "UNKNOWN"
    assert run(cid, item, {"context": {"created_at": "2026-10-10T00:00:00Z"}})[0] == "PASS"


def test_composer_and_workbench_defaults():
    assert run("gcp.htbp.composer.no_default_compute_sa", {"name": "projects/p/locations/r/environments/e", "config": {}})[0] == "FAIL"
    assert run("gcp.htbp.workbench.no_default_compute_sa", {"name": "projects/p/locations/z/instances/n", "gceSetup": {}})[0] == "FAIL"


def test_scheduler_replay_patterns():
    cid = "gcp.htbp.scheduler.no_recurring_access_regrant"
    base = case(cid, "fail")
    for uri, method, status in (
            ("https://iam.googleapis.com/v1/projects/p/serviceAccounts/a@p.iam.gserviceaccount.com/keys", "POST", "FAIL"),
            ("https://storage.googleapis.com/storage/v1/b/bucket/iam", "PUT", "FAIL"),
            ("https://compute.googleapis.com/compute/v1/projects/p/global/firewalls", "POST", "FAIL"),
            ("https://cloudresourcemanager.googleapis.com/v1/projects/p:getIamPolicy", "POST", "PASS"),
            ("https://cloudresourcemanager.googleapis.com/v1/projects/p:setIamPolicy", "GET", "PASS")):
        base["httpTarget"].update(uri=uri, httpMethod=method)
        assert run(cid, base)[0] == status, uri
    paused = case(cid, "fail")
    paused["state"] = "PAUSED"
    assert run(cid, paused)[0] == "NOT_APPLICABLE"
    oidc = case(cid, "fail")
    oidc["httpTarget"] = {"uri": "https://cloudresourcemanager.googleapis.com/v1/projects/p:setIamPolicy", "oidcToken": {"serviceAccountEmail": "x"}}
    assert run(cid, oidc)[0] == "NOT_APPLICABLE"


def test_effective_org_policy_guardrails():
    from peaso.checks.hacktricks_bp_gcp import _orgpol_index, _PROJECT
    keys = "gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked"
    on, off = [{"enforce": True}], [{"enforce": False}]
    # Legacy booleans alone block both paths when no managed policy is set.
    both = _orgpol_index(iam_disableServiceAccountKeyCreation=on, iam_disableServiceAccountKeyUpload=on)
    assert run(keys, _PROJECT, both)[0] == "PASS"
    assert run(keys, _PROJECT, _orgpol_index(iam_disableServiceAccountKeyCreation=on))[0] == "FAIL"  # upload still open
    conditional = _orgpol_index(iam_disableServiceAccountKeyCreation=[{"enforce": True, "condition": {"expression": "x"}}])
    assert run(keys, _PROJECT, conditional)[0] == "UNKNOWN"
    contradictory = _orgpol_index(iam_disableServiceAccountKeyCreation=[{"enforce": True}, {"enforce": False}])
    assert run(keys, _PROJECT, contradictory)[0] == "UNKNOWN"
    partial = _orgpol_index()
    partial["collections"]["org_policy_effective"][0]["status"] = "partial"
    assert run(keys, _PROJECT, partial)[0] == "UNKNOWN"
    missing_row = _orgpol_index()
    missing_row["org_policy_effective"].pop(0)
    assert run(keys, _PROJECT, missing_row)[0] == "UNKNOWN"
    cross = "gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled"
    assert run(cross, _PROJECT, _orgpol_index(iam_disableCrossProjectServiceAccountUsage=on))[0] == "PASS"
    drs = "gcp.htbp.orgpolicy.domain_restricted_sharing"
    assert run(drs, _PROJECT, _orgpol_index())[0] == "FAIL"  # unset list constraint allows any member
    assert run(drs, _PROJECT, _orgpol_index(iam_allowedPolicyMemberDomains=[{"values": {"deniedValues": ["x"]}}]))[0] == "FAIL"
    assert run(drs, _PROJECT, _orgpol_index(iam_allowedPolicyMemberDomains=[{"denyAll": True}]))[0] == "PASS"
    assert run(drs, _PROJECT, _orgpol_index(iam_allowedPolicyMemberDomains=[{"enforce": True}]))[0] == "UNKNOWN"
    managed = _orgpol_index(iam_managed_allowedPolicyMembers=[{"enforce": True, "parameters": {"allowedPrincipalSets": ["//cloudresourcemanager.googleapis.com/organizations/1"]}}],
                            iam_allowedPolicyMemberDomains=[{"allowAll": True}])
    assert run(drs, _PROJECT, managed)[0] == "PASS"  # managed policy supersedes the legacy list
    grants = "gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled"
    assert run(grants, _PROJECT, _orgpol_index(iam_managed_preventPrivilegedBasicRolesForDefaultServiceAccounts=on))[0] == "PASS"
    assert run(grants, _PROJECT, _orgpol_index(iam_automaticIamGrantsForDefaultServiceAccounts=on,
               iam_managed_preventPrivilegedBasicRolesForDefaultServiceAccounts=off))[0] == "FAIL"
    contacts = "gcp.htbp.orgpolicy.essential_contacts_domain_restricted"
    assert run(contacts, _PROJECT, _orgpol_index(essentialcontacts_allowedContactDomains=[{"values": {"allowedValues": ["@example.com"]}}]))[0] == "PASS"


def test_org_policy_explicit_true_false_and_unset():
    from peaso.checks.hacktricks_bp_gcp import _orgpol_index, _PROJECT
    on, off = [{"enforce": True}], [{"enforce": False}]
    allow = [{"values": {"allowedValues": ["C0abc123"]}}]
    cases = {
        # check: (explicit-true index rules, explicit-false index rules, unset status)
        "gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled":
            ({"iam_disableCrossProjectServiceAccountUsage": on}, {"iam_disableCrossProjectServiceAccountUsage": off}, "UNKNOWN"),
        "gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked":
            ({"iam_disableServiceAccountKeyCreation": on, "iam_disableServiceAccountKeyUpload": on},
             {"iam_disableServiceAccountKeyCreation": off, "iam_disableServiceAccountKeyUpload": off}, "FAIL"),
        "gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled":
            ({"iam_automaticIamGrantsForDefaultServiceAccounts": on}, {"iam_automaticIamGrantsForDefaultServiceAccounts": off}, "FAIL"),
        "gcp.htbp.orgpolicy.domain_restricted_sharing":
            ({"iam_allowedPolicyMemberDomains": allow}, {"iam_allowedPolicyMemberDomains": [{"allowAll": True}]}, "FAIL"),
        "gcp.htbp.orgpolicy.essential_contacts_domain_restricted":
            ({"essentialcontacts_allowedContactDomains": [{"values": {"allowedValues": ["@example.com"]}}]},
             {"essentialcontacts_allowedContactDomains": [{"allowAll": True}]}, "FAIL"),
    }
    for cid, (true_rules, false_rules, unset) in cases.items():
        assert run(cid, _PROJECT, _orgpol_index(**true_rules))[0] == "PASS", cid
        assert run(cid, _PROJECT, _orgpol_index(**false_rules))[0] == "FAIL", cid
        assert run(cid, _PROJECT, _orgpol_index())[0] == unset, cid
    status, evidence = run("gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled", _PROJECT, _orgpol_index())
    assert status == "UNKNOWN" and "explicit enforce:true" in evidence["reason"]


def test_pool_wide_principal_set_only_matches_whole_pool():
    cid = "gcp.htbp.iam.policy_no_pool_wide_workload_principal_set"
    item = case(cid, "fail")
    item["bindings"][0]["members"] = ["principalSet://iam.googleapis.com/locations/global/workforcePools/staff/*"]
    assert run(cid, item)[0] == "PASS"  # workforce pools are out of scope for this check
    item["bindings"][0]["members"] = ["principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/gh/group/admins"]
    assert run(cid, item)[0] == "PASS"
    item = case(cid, "fail")
    item["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    status, evidence = run(cid, item)
    assert status == "FAIL" and evidence["pool_wide_bindings"][0]["conditional"] is True
