"""Opt-in schema v2 joins and regression guards."""
from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import ACCOUNT, ALICE, allow, entry, errors_of, pol, reached, snapshot
from tests.test_peaso_privesc_schema_ext_k8s import crole, crb, k8s_snap, rb, sa, user

POLICY = f"arn:aws:iam::{ACCOUNT}:policy/editable"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/target"
AWS_ENTRY = entry("aws-t-v2-policy", "aws", {"all_of": [
    {"action": "iam:CreatePolicyVersion", "resource": "{source.assumable_role_attached_policy_arn}"}]},
    {"kind": "aws_account_admin", "selector": {
        "via_assumable_role_attached_policy_covered_by": "iam:CreatePolicyVersion"},
     "scope": "same_account", "outcome": "scope_control"})


def aws_snap(*, edit=True, trust=True, versions=1, delete=False, policy_status="collected", boundary=False):
    rights = [allow("sts:AssumeRole", ROLE)]
    if edit:
        rights.append(allow("iam:CreatePolicyVersion", POLICY))
    if delete:
        rights.append(allow("iam:DeletePolicyVersion", POLICY))
    principal = {"UserName": "alice", "Arn": ALICE, "GroupList": [], "AttachedManagedPolicies": [],
                 "UserPolicyList": [{"PolicyName": "rights", "PolicyDocument": pol(*rights)}]}
    role = {"RoleName": "target", "Arn": ROLE, "RolePolicyList": [],
            "AssumeRolePolicyDocument": pol({"Effect": "Allow", "Principal": {"AWS": ALICE if trust else "arn:aws:iam::999999999999:root"},
                                             "Action": "sts:AssumeRole"}),
            "AttachedManagedPolicies": [{"PolicyArn": POLICY, "PolicyName": "editable"}], "InstanceProfileList": []}
    if boundary:
        role["PermissionsBoundary"] = {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/readonly"}
    managed = {"Arn": POLICY, "PolicyName": "editable", "PolicyVersionList": [
        {"VersionId": f"v{i}", "IsDefaultVersion": i == 0, "Document": pol(allow("s3:GetObject", "*"))}
        for i in range(versions)]}
    policies = [managed]
    if boundary:
        policies.append({"Arn": f"arn:aws:iam::{ACCOUNT}:policy/readonly", "PolicyName": "readonly",
                         "PolicyVersionList": [{"IsDefaultVersion": True, "Document": pol(allow("s3:GetObject", "*"))}]})
    scope = ACCOUNT + "/us-east-1"
    return snapshot("aws", [("iam_user", scope, [principal]), ("iam_role", scope, [role]),
                            ("iam_policy", scope, policies if policy_status == "collected" else [], policy_status),
                            ("iam_group", scope, []), ("scp_policy", scope, [], "empty")])


def test_aws_v2_join_pass_no_path_unknown_and_capacity():
    assert errors_of(AWS_ENTRY) == []
    def result(**kw):
        return privesc.analyze(aws_snap(**kw), entries=[AWS_ENTRY])
    assert reached(result(), ALICE).get(f"aws_account_admin:{ACCOUNT}") == "derived"
    for kw in ({"edit": False}, {"trust": False}, {"versions": 5}, {"boundary": True}):
        assert f"aws_account_admin:{ACCOUNT}" not in reached(result(**kw), ALICE)
    assert reached(result(versions=5, delete=True), ALICE).get(f"aws_account_admin:{ACCOUNT}") == "derived"
    unknown = privesc.analyze(aws_snap(policy_status="not_collected"), entries=[AWS_ENTRY], include_unknown=True)
    assert not any(f["status"] == "FAIL" for f in unknown["findings"])
    assert f"aws_account_admin:{ACCOUNT}" not in reached(unknown, ALICE)
    assert any(f["status"] == "UNKNOWN" for f in unknown["findings"])
    capacity_unknown = aws_snap()
    next(c for c in capacity_unknown["collections"] if c["type"] == "iam_policy")["items"][0].pop("PolicyVersionList")
    capacity = privesc.analyze(capacity_unknown, entries=[AWS_ENTRY])
    assert reached(capacity, ALICE).get(f"aws_account_admin:{ACCOUNT}") == "conditional"


def test_aws_v2_validator_rejects_unpaired_or_wrong_action():
    for change in (lambda e: e["target"]["selector"].clear(),
                   lambda e: e["target"]["selector"].update(via_assumable_role_attached_policy_covered_by="iam:SetDefaultPolicyVersion"),
                   lambda e: e["requires"]["all_of"][0].update(action="iam:SetDefaultPolicyVersion")):
        e = copy.deepcopy(AWS_ENTRY)
        change(e)
        assert errors_of(e)
    e = copy.deepcopy(AWS_ENTRY)
    e["requires"] = {"any_of": [AWS_ENTRY["requires"], {"all_of": [{"action": "sts:AssumeRole", "resource": "*"}]}]}
    assert errors_of(e)


def test_aws_v2_existing_denies_scp_and_malformed_capacity():
    def result(snap):
        return reached(privesc.analyze(snap, entries=[AWS_ENTRY]), ALICE)
    snap = aws_snap()
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["RolePolicyList"] = [{"PolicyName": "limit", "PolicyDocument": pol(
        {"Effect": "Deny", "Action": "s3:*", "Resource": "*"})}]
    assert f"aws_account_admin:{ACCOUNT}" not in result(snap)

    snap = aws_snap()
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role.pop("AttachedManagedPolicies")
    out = privesc.analyze(snap, entries=[AWS_ENTRY], include_unknown=True)
    assert f"aws_account_admin:{ACCOUNT}" not in reached(out, ALICE)
    assert any(f["status"] == "UNKNOWN" for f in out["findings"])

    snap = aws_snap()
    scp = next(c for c in snap["collections"] if c["type"] == "scp_policy")
    scp.update(status="collected", items=[{"Id": "p1", "TargetId": ACCOUNT,
        "Detail": {"Policy": {"Content": pol(
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:*", "Resource": "*"})}}}])
    assert f"aws_account_admin:{ACCOUNT}" not in result(snap)

    snap = aws_snap()
    scp = next(c for c in snap["collections"] if c["type"] == "scp_policy")
    scp.update(status="collected", items=[{"Id": "p2", "TargetId": ACCOUNT,
        "Detail": {"Policy": {"Content": pol(
            {"Effect": "Allow", "Action": "iam:*", "Resource": "*"})}}}])
    assert f"aws_account_admin:{ACCOUNT}" not in result(snap)

    snap = aws_snap()
    versions = next(c for c in snap["collections"] if c["type"] == "iam_policy")["items"][0]["PolicyVersionList"]
    versions[0].pop("VersionId")
    assert result(snap).get(f"aws_account_admin:{ACCOUNT}") == "conditional"


GCP_ENTRY = entry("gcp-t-v2-running", "gcp", {"all_of": [{"action": "container.pods.exec", "resource": "{target.scope}"}]},
                  {"kind": "k8s_service_account", "selector": {"k8s_sa_used_by_running_pod": True},
                   "scope": "cluster", "outcome": "credentials"})


def gcp_snap():
    return snapshot("gcp", [("project", "projects/p1", [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
                            ("iam_policy", "projects/p1", [{"name": "projects/p1", "bindings": [
                                {"role": "projects/p1/roles/exec", "members": ["user:alice@x.com"]}]}]),
                            ("iam_role", "projects/p1", [{"name": "projects/p1/roles/exec", "includedPermissions": ["container.pods.exec"]}]),
                            ("service_account", "projects/p1", []),
                            ("gke_cluster", "projects/p1", [{"name": "c1", "location": "us-a"}]),
                            ("iam_deny_policy", "projects/p1", [], "empty")])


def k8s_related(*, phase="Running", mount=True, projected=False, pod_status="collected"):
    spec = {"serviceAccountName": "builder", "automountServiceAccountToken": mount}
    if projected:
        spec["volumes"] = [{"name": "token", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}]
        spec["containers"] = [{"name": "c", "volumeMounts": [{"name": "token", "mountPath": "/var/run/token"}]}]
    pod = {"kind": "Pod", "metadata": {"name": "p", "namespace": "a"}, "provenance": {"cluster_id": "gke_p1_us-a_c1"},
           "spec": spec, "status": {"phase": phase}}
    service = {"kind": "ServiceAccount", "metadata": {"name": "builder", "namespace": "a"},
               "provenance": {"cluster_id": "gke_p1_us-a_c1"}}
    return snapshot("k8s", [("serviceaccount", "gke_p1_us-a_c1", [service]),
                            ("pod", "gke_p1_us-a_c1", [pod] if pod_status == "collected" else [], pod_status)])


def test_gcp_v2_running_pod_pass_no_path_and_unresolved():
    assert errors_of(GCP_ENTRY) == []
    def result(related, *, include_unknown=False):
        return privesc.analyze(gcp_snap(), entries=[GCP_ENTRY], related_snapshots=related,
                               include_unknown=include_unknown)
    target = "k8s:gke_p1_us-a_c1:sa:a:builder"
    assert target in reached(result([k8s_related()]), "user:alice@x.com")
    assert target in reached(result([k8s_related(mount=False, projected=True)]), "user:alice@x.com")
    for related in ([k8s_related(phase="Pending")], [k8s_related(mount=False)]):
        assert target not in reached(result(related), "user:alice@x.com")
    for related in ([], [k8s_related(pod_status="not_collected")], [k8s_related(), k8s_related()]):
        out = result(related, include_unknown=True)
        assert target not in reached(out, "user:alice@x.com")
        assert not any(f["status"] == "FAIL" and f["resource_id"] == target for f in out["findings"])
        assert any(f["status"] == "UNKNOWN" for f in out["findings"])


def test_gcp_v2_validator_rejects_mixed_ksa_selectors():
    e = copy.deepcopy(GCP_ENTRY)
    e["target"]["selector"]["k8s_sa_in_cluster"] = True
    assert errors_of(e)


def test_gcp_v2_unproven_token_does_not_reach_ksa():
    related = k8s_related(mount=False, projected=True)
    pod = next(c for c in related["collections"] if c["type"] == "pod")["items"][0]
    pod["spec"]["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"].pop("path")
    out = privesc.analyze(gcp_snap(), entries=[GCP_ENTRY], related_snapshots=[related])
    assert "k8s:gke_p1_us-a_c1:sa:a:builder" not in reached(out, "user:alice@x.com")

    related = k8s_related()
    pod = next(c for c in related["collections"] if c["type"] == "pod")["items"][0]
    pod["spec"]["automountServiceAccountToken"] = "unknown"
    out = privesc.analyze(gcp_snap(), entries=[GCP_ENTRY], related_snapshots=[related], include_unknown=True)
    assert "k8s:gke_p1_us-a_c1:sa:a:builder" not in reached(out, "user:alice@x.com")
    assert any(f["status"] == "UNKNOWN" for f in out["findings"])


K8S_ENTRY = entry("k8s-t-v2-rolebound", "k8s", {"all_of": [
    {"verb": "escalate", "resource": "clusterroles", "api_group": "rbac.authorization.k8s.io", "namespace": "*",
     "resource_name": "{source_rolebound_clusterrole}"},
    {"verb": "patch", "resource": "clusterroles", "api_group": "rbac.authorization.k8s.io", "namespace": "*",
     "resource_name": "{source_rolebound_clusterrole}"}]},
    {"kind": "k8s_service_account", "selector": {"k8s_sa_in_namespace": "{target.namespace}"},
     "scope": "same_namespace", "outcome": "identity"})


def test_k8s_v2_rolebinding_same_name_same_namespace():
    assert errors_of(K8S_ENTRY) == []
    edit = crole("edit", [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
                           "verbs": ["escalate", "patch"], "resourceNames": ["bound"]}])
    bound = crole("bound", [])
    subject = user("dev")
    def result(rbs):
        snap = k8s_snap(clusterroles=[edit, bound], crbs=[crb("edit-grant", "edit", subject)],
                        rbs=rbs, sas=[sa("victim", "a"), sa("other", "b")], namespaces=("a", "b"))
        return privesc.analyze(snap, entries=[K8S_ENTRY])
    source = "k8s:c1:user:dev"
    assert "k8s:c1:sa:a:victim" in reached(result([rb("bound-grant", "a", "bound", subject)]), source)
    assert "k8s:c1:sa:b:other" not in reached(result([rb("bound-grant", "a", "bound", subject)]), source)
    assert "k8s:c1:sa:a:victim" not in reached(result([]), source)
    assert "k8s:c1:sa:a:victim" not in reached(result([rb("other-grant", "a", "edit", subject)]), source)
    incomplete = k8s_snap(clusterroles=[edit, bound], crbs=[crb("edit-grant", "edit", subject)],
                          sas=[sa("victim", "a")])
    incomplete["collections"] = [c for c in incomplete["collections"] if c["type"] != "rolebinding"]
    out = privesc.analyze(incomplete, entries=[K8S_ENTRY], include_unknown=True)
    assert "k8s:c1:sa:a:victim" not in reached(out, source)
    assert any(f["status"] == "UNKNOWN" for f in out["findings"])
    assert any(c.get("kind") == "collection" and "rolebinding" in c.get("reason", "") for c in out["coverage"])


def test_k8s_v2_validator_rejects_missing_second_verb():
    e = copy.deepcopy(K8S_ENTRY)
    e["requires"]["all_of"].pop()
    assert errors_of(e)
