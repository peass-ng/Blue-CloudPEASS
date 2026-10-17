"""Catalog follow-ups over the aws_facts_ext facts: EKS access entries / Pod Identity associations joined from a related
AWS snapshot into the K8s model, Amplify Admin token ARN, Cognito identity-pool roles as {target.attached_resource_arn},
Image Builder component inputs. Each item: PASS/edge when the facts are present, needs-facts / unresolved when missing."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc import schema

from test_peaso_privesc_audit_fixes import _k8s_nodes
from test_peaso_privesc_audit_fixes import aws as k8s_aws
from test_peaso_privesc_audit_fixes import role as k8s_role
from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, catalog_entry as active_catalog_entry, archived_catalog_entry, edges, pol, reached, role, trust_service, user


def catalog_entry(eid):
    return archived_catalog_entry(eid) if eid in {"aws-cognito-updateidentitypool", "aws-amplifybackend-gettoken-studio-admin"} else active_catalog_entry(eid)

REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
NODE_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ec2-role"
NODE_ID = "k8s-cloud-eks-node-role-to-node"


def arn(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def analyze(snap, eid, **kw):
    return privesc.analyze(snap, entries=[catalog_entry(eid)], **kw)


def statuses(result, eid):
    return sorted(f["status"] for f in result["findings"] if f["check_id"] == eid)


def needs(result, key):
    return [c["impact"] for c in result["coverage"] if c.get("reason") == f"selector {key} not evaluated"]


def unresolved_only(result, source):
    found = edges(result, source)
    return bool(found) and all(e["target"].startswith(("unresolved:", "unknown:")) and e["confidence"] == "unknown" for e in found)


# --- 1) EKS access entries -> k8s_nodes_mapped_to_cloud_identity / eks_access_entry_type ----------------------
def _eks_aws(entries=None):
    inst = {"InstanceId": "i-1", "AccountId": ACCOUNT, "Region": REGION, "State": {"Name": "running"},
            "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/ec2-role"}, "MetadataOptions": {}}
    extra = [("instance", SCOPE, [inst], "collected")]
    if entries is not None:
        extra.append(("eks_access_entry", SCOPE, entries, "collected" if entries else "empty"))
    return k8s_aws([], [k8s_role("ec2-role")], extra)


def _node_entry(kind="EC2_LINUX", principal=NODE_ROLE):
    return [{"clusterName": "c1", "principalArn": principal, "type": kind, "id": f"c1/{principal}"}]


def test_eks_node_access_entry_maps_node_role_to_its_node():
    result = analyze(_k8s_nodes("aws:///us-east-1a/i-1"), NODE_ID, related_snapshots=[_eks_aws(_node_entry())])
    assert reached(result, f"cloud:eks_node:{NODE_ROLE}").get("k8s:c1:node:n1") == "derived"
    assert statuses(result, NODE_ID) == ["FAIL"]


def test_eks_access_entries_missing_report_needed_facts():
    result = analyze(_k8s_nodes("aws:///us-east-1a/i-1"), NODE_ID, related_snapshots=[_eks_aws(None)])
    assert "k8s:c1:node:n1" not in reached(result, f"cloud:eks_node:{NODE_ROLE}")
    assert statuses(result, NODE_ID) != ["FAIL"]
    assert needs(result, "k8s_nodes_mapped_to_cloud_identity") == [
        "Matching targets reported as one unresolved placeholder per scope (no members); needs "
        + schema.FACTS_NEEDED["k8s_nodes_mapped_to_cloud_identity"]]


def test_eks_access_entry_of_another_type_or_absent():
    standard = analyze(_k8s_nodes("aws:///us-east-1a/i-1"), NODE_ID, related_snapshots=[_eks_aws(_node_entry("STANDARD"))])
    assert "k8s:c1:node:n1" not in reached(standard, f"cloud:eks_node:{NODE_ROLE}")
    # Entries collected but none for the node role: mapping via aws-auth (contents not collected) -> conditional.
    other = analyze(_k8s_nodes("aws:///us-east-1a/i-1"), NODE_ID,
                    related_snapshots=[_eks_aws(_node_entry(principal=arn("other")))])
    assert reached(other, f"cloud:eks_node:{NODE_ROLE}").get("k8s:c1:node:n1") == "conditional"


def test_eks_pod_identity_association_binds_service_account():
    pi_role = arn("pi-role")
    assoc = [{"clusterName": "c1", "namespace": "a", "serviceAccount": "builder", "roleArn": pi_role, "associationId": "x"}]

    def run(trust, associations):
        extra = [] if associations is None else [("eks_pod_identity_association", SCOPE, associations, "collected")]
        return analyze(_k8s_nodes("aws:///us-east-1a/i-1"), "k8s-cloud-eks-pod-identity",
                       related_snapshots=[k8s_aws([], [k8s_role("pi-role", trust)], extra)])
    ident = f"cloud:eks_pod_identity:{pi_role}"
    assert reached(run("pods.eks.amazonaws.com", assoc), "k8s:c1:sa:a:builder") == {ident: "derived"}
    assert reached(run("ec2.amazonaws.com", assoc), "k8s:c1:sa:a:builder") == {ident: "conditional"}
    assert reached(run("pods.eks.amazonaws.com", None), "k8s:c1:sa:a:builder") == {}


# --- 3) Amplify Admin token resource ---------------------------------------------------------------------------
APP = f"arn:aws:amplify:{REGION}:{ACCOUNT}:apps/d1"
TOKEN = f"arn:aws:amplifybackend:{REGION}:{ACCOUNT}:/backend/d1/challenge/*"
BACKEND = f"arn:aws:amplifybackend:{REGION}:{ACCOUNT}:/backend/d1/*"


def _amplify(backends=True):
    status = {"collection_status": "collected", "items": [{"environmentName": "dev"}]} if backends else {"collection_status": "denied"}
    return [("amplify_app", SCOPE, [{"appArn": APP, "appId": "d1", "BackendEnvironments": status}])]


def test_amplifybackend_createtoken_on_token_resource():
    eid = "aws-amplifybackend-createtoken-studio-admin"
    good = user("alice", allow("amplify:GetApp", APP), allow("amplifybackend:CreateToken", f"arn:aws:amplifybackend:{REGION}:{ACCOUNT}:/backend/d1/*"))
    result = analyze(aws_snap([good], [], _amplify()), eid)
    assert set(reached(result, ALICE)) == {f"aws_service_plane_admin:amplifybackend:{APP}"}
    # CreateToken granted on the Amplify app ARN only does not authorize the amplifybackend token resource.
    app_only = user("alice", allow("amplify:GetApp", APP), allow("amplifybackend:CreateToken", APP))
    assert reached(analyze(aws_snap([app_only], [], _amplify()), eid), ALICE) == {}
    # CreateToken/GetToken need both the backend (/backend/<AppId>/*) and the token resource (Service Authorization Reference).
    exact = user("alice", allow("amplify:GetApp", APP), allow("amplifybackend:CreateToken", [TOKEN, BACKEND]))
    assert set(reached(analyze(aws_snap([exact], [], _amplify()), eid), ALICE)) == {f"aws_service_plane_admin:amplifybackend:{APP}"}
    # A token-only grant overlaps the backend pattern (/backend/d1/challenge/* is inside /backend/d1/*), so the evaluator's
    # wildcard-overlap rule keeps it; a backend grant of another app does not.
    token_only = user("alice", allow("amplify:GetApp", APP), allow("amplifybackend:CreateToken", TOKEN))
    assert set(reached(analyze(aws_snap([token_only], [], _amplify()), eid), ALICE)) == {f"aws_service_plane_admin:amplifybackend:{APP}"}
    other_app = user("alice", allow("amplify:GetApp", APP), allow("amplifybackend:CreateToken", BACKEND.replace("/d1/", "/d2/")))
    assert reached(analyze(aws_snap([other_app], [], _amplify()), eid), ALICE) == {}


def test_amplifybackend_backends_not_collected_stay_unresolved():
    alice = user("alice", allow("amplify:GetApp"), allow("amplifybackend:GetToken"))
    result = analyze(aws_snap([alice], [], _amplify(backends=False)), "aws-amplifybackend-gettoken-studio-admin", include_unknown=True)
    assert unresolved_only(result, ALICE)


# --- 4) Cognito UpdateIdentityPool -> identity pool of the role -------------------------------------------------
POOL_ID = "us-east-1:abc"
IDENTITY_POOL = f"arn:aws:cognito-identity:{REGION}:{ACCOUNT}:identitypool/{POOL_ID}"


def _cognito(roles_status="collected"):
    trust = pol({"Effect": "Allow", "Principal": {"Federated": "cognito-identity.amazonaws.com"}, "Action": "sts:AssumeRoleWithWebIdentity"})
    roles = [role("auth", trust), role("other", trust)]
    pool = {"IdentityPoolId": POOL_ID, "Configuration": {"collection_status": "collected", "CognitoIdentityProviders": []},
            "Roles": {"collection_status": roles_status, "Roles": {"authenticated": arn("auth")} if roles_status == "collected" else {}}}
    return roles, [("cognito_identity_pool", SCOPE, [pool])]


def test_updateidentitypool_reaches_roles_of_covered_pool():
    roles, extra = _cognito()
    result = analyze(aws_snap([user("alice", allow("cognito-identity:UpdateIdentityPool", IDENTITY_POOL))], roles, extra),
                     "aws-cognito-updateidentitypool")
    assert set(reached(result, ALICE)) == {arn("auth")}
    other = analyze(aws_snap([user("alice", allow("cognito-identity:UpdateIdentityPool", IDENTITY_POOL + "x"))], roles, extra),
                    "aws-cognito-updateidentitypool")
    assert reached(other, ALICE) == {}


def test_updateidentitypool_roles_not_collected_stay_unresolved():
    roles, extra = _cognito("denied")
    result = analyze(aws_snap([user("alice", allow("cognito-identity:UpdateIdentityPool"))], roles, extra),
                     "aws-cognito-updateidentitypool", include_unknown=True)
    assert unresolved_only(result, ALICE)
    assert statuses(result, "aws-cognito-updateidentitypool") != ["FAIL"]


# --- 5) Image Builder consumer_input_writable_via --------------------------------------------------------------
PIPELINE = f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-pipeline/p"
IB_ID = "aws-imagebuilder-component-version-hijack"


COMPONENT = f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:component"


def _imagebuilder(collected=True, components=None):
    roles = [role("builder", trust_service("ec2.amazonaws.com"), profile=True)]
    pipeline = {"arn": PIPELINE, "InstanceProfileName": "builder",
                "imageRecipeArn": f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:image-recipe/r/1.0.0"}
    if components is not None:
        pipeline["RecipeComponents"] = components
    extra = [("imagebuilder_pipeline", SCOPE, [pipeline])] if collected else []
    return roles, extra


def _ib_user(component_resource):
    return user("alice", allow("imagebuilder:CreateComponent", component_resource),
                allow("imagebuilder:StartImagePipelineExecution", PIPELINE))


def _recipe(*arns):
    return {"collection_status": "collected", "items": list(arns)}


def test_imagebuilder_recipe_components_match_exact_name_scoped_grant():
    roles, extra = _imagebuilder(components=_recipe(f"{COMPONENT}/app/1.x.x", f"arn:aws:imagebuilder:{REGION}:aws:component/update-linux/x.x.x"))
    # Name-scoped grant: a new version of "app" is arn:...:component/app/<version>/<build>.
    assert reached(analyze(aws_snap([_ib_user(f"{COMPONENT}/app/*")], roles, extra), IB_ID), ALICE) == {arn("builder"): "conditional"}
    assert reached(analyze(aws_snap([_ib_user(f"{COMPONENT}/other/*")], roles, extra), IB_ID), ALICE) == {}
    # AWS-owned wildcard component is not writable by the account.
    aws_only = _imagebuilder(components=_recipe(f"arn:aws:imagebuilder:{REGION}:aws:component/update-linux/x.x.x"))
    assert reached(analyze(aws_snap([_ib_user("*")], *aws_only), IB_ID), ALICE) == {}


def test_imagebuilder_recipe_components_wildcard_grant_and_pinned_recipe():
    roles, extra = _imagebuilder(components=_recipe(f"{COMPONENT}/app/1.2.x/1", f"{COMPONENT}/pinned/1.0.0/3"))
    result = analyze(aws_snap([_ib_user(f"{COMPONENT}/*")], roles, extra), IB_ID)
    assert reached(result, ALICE) == {arn("builder"): "conditional"}
    assert [e for e in edges(result, ALICE) if e["target"] == arn("builder")]
    pinned = _imagebuilder(components=_recipe(f"{COMPONENT}/pinned/1.0.0/3", f"{COMPONENT}/semver/2.0.0"))
    assert reached(analyze(aws_snap([_ib_user(f"{COMPONENT}/*")], *pinned), IB_ID), ALICE) == {}


def test_imagebuilder_recipe_not_collected_falls_back_conditional():
    for components in (None, {"collection_status": "denied", "error": {"code": "AccessDeniedException"}}):
        roles, extra = _imagebuilder(components=components)
        # Without recipe facts the input is the Region's component/*: any overlapping grant stays conditional, and a
        # grant in another Region does not match.
        assert reached(analyze(aws_snap([_ib_user(f"{COMPONENT}/*")], roles, extra), IB_ID), ALICE) == {arn("builder"): "conditional"}
        assert reached(analyze(aws_snap([_ib_user(f"{COMPONENT}/app/*")], roles, extra), IB_ID), ALICE) == {arn("builder"): "conditional"}
        assert reached(analyze(aws_snap([_ib_user(f"arn:aws:imagebuilder:eu-west-1:{ACCOUNT}:component/*")], roles, extra), IB_ID), ALICE) == {}


def test_imagebuilder_component_input_resolved_from_pipeline():
    roles, extra = _imagebuilder()
    alice = user("alice", allow("imagebuilder:CreateComponent", f"arn:aws:imagebuilder:{REGION}:{ACCOUNT}:component/*"),
                 allow("imagebuilder:StartImagePipelineExecution", PIPELINE))
    result = analyze(aws_snap([alice], roles, extra), IB_ID)
    assert reached(result, ALICE) == {arn("builder"): "conditional"}
    other_region = user("alice", allow("imagebuilder:CreateComponent", f"arn:aws:imagebuilder:eu-west-1:{ACCOUNT}:component/*"),
                        allow("imagebuilder:StartImagePipelineExecution", PIPELINE))
    assert reached(analyze(aws_snap([other_region], roles, extra), IB_ID), ALICE) == {}


def test_imagebuilder_pipelines_not_collected_stay_unresolved():
    roles, extra = _imagebuilder(collected=False)
    alice = user("alice", allow("imagebuilder:CreateComponent"), allow("imagebuilder:StartImagePipelineExecution"))
    result = analyze(aws_snap([alice], roles, extra), IB_ID)
    assert arn("builder") not in reached(result, ALICE)
    assert statuses(result, IB_ID) != ["FAIL"]
