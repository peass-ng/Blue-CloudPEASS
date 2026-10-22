"""EKS access and endpoint rules preserve the relevant distinction and privacy."""

from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

from peaso.attack_detection.aws_eks_access_batch192 import normalize
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-lab-role"
ADMIN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"


def event(name, request):
    return {
        "eventSource": "eks.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"name": "synthetic-cluster", **request},
        "responseElements": {},
    }


def test_cluster_admin_policy_requires_exact_policy_and_cluster_scope():
    row = event("AssociateAccessPolicy", {
        "principalArn": quote(ROLE, safe=""), "policyArn": ADMIN,
        "accessScope": {"type": "cluster"},
    })
    signals = normalize(row)
    assert len(signals) == 1
    assert signals[0]["request.eks_cluster_admin_policy_granted"] is True
    assert signals[0]["target.id"].startswith("sha256:")
    assert ROLE not in str(signals) and "synthetic-cluster" not in str(signals)
    for field, value in (
        ("policyArn", "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"),
        ("accessScope", {"type": "namespace", "namespaces": ["default"]}),
    ):
        altered = deepcopy(row)
        altered["requestParameters"][field] = value
        assert normalize(altered) == []
    denied = deepcopy(row)
    denied["errorCode"] = "ResourceNotFoundException"
    assert normalize(denied) == []
    service = deepcopy(row)
    service["userIdentity"]["invokedBy"] = "eks.amazonaws.com"
    assert normalize(service) == []


def test_access_entry_creation_and_group_change_are_distinct():
    created = event("CreateAccessEntry", {"principalArn": ROLE})
    assert normalize(created)[0]["request.eks_access_entry_created"] is True
    assert "request.eks_access_groups_configured" not in normalize(created)[0]
    created["requestParameters"]["kubernetesGroups"] = ["synthetic-admins"]
    assert normalize(created)[0]["request.eks_access_groups_configured"] is True
    updated = event("UpdateAccessEntry", {
        "principalArn": quote(ROLE, safe=""), "kubernetesGroups": ["synthetic-admins"],
    })
    assert normalize(updated)[0]["request.eks_access_groups_configured"] is True
    assert "request.eks_access_entry_created" not in normalize(updated)[0]
    updated["requestParameters"]["kubernetesGroups"] = []
    assert normalize(updated) == []


def test_pod_identity_role_binding_and_guardrail_change_are_bounded():
    created = event("CreatePodIdentityAssociation", {
        "namespace": "synthetic", "serviceAccount": "synthetic-service",
        "roleArn": ROLE,
    })
    assert normalize(created)[0]["request.eks_pod_identity_role_bound"] is True
    assert ROLE not in str(normalize(created))
    updated = event("UpdatePodIdentityAssociation", {
        "associationId": "synthetic-association", "disableSessionTags": True,
    })
    assert normalize(updated)[0]["request.eks_pod_identity_association_repointed"] is True
    updated["requestParameters"]["disableSessionTags"] = False
    assert normalize(updated) == []


def test_public_endpoint_signal_requires_world_cidr_and_integrates_with_rule(tmp_path: Path):
    row = event("UpdateClusterConfig", {
        "resourcesVpcConfig": {
            "endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"],
        },
    })
    (tmp_path / "eks.yml").write_text("""title: Synthetic EKS public endpoint
id: 19200000-0000-4000-8000-000000000099
status: experimental
description: Synthetic integration test.
references: [https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterConfig.html]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: eks.amazonaws.com
    event.name: UpdateClusterConfig
    event.outcome: success
    request.eks_public_api_exposed: true
  condition: selection
falsepositives: [Approved public endpoint]
level: high
x_hacktricks_technique_id: synthetic-eks-public-endpoint
""", encoding="utf-8")
    selected = load_rules(tmp_path, product="aws")
    assert len(detect_aws_events([row], selected)) == 1
    narrow = deepcopy(row)
    narrow["requestParameters"]["resourcesVpcConfig"]["publicAccessCidrs"] = ["203.0.113.0/24"]
    denied = deepcopy(row)
    denied["errorCode"] = "ResourceNotFoundException"
    assert detect_aws_events([narrow, denied], selected) == []
