"""Service Catalog launch role edges require a modified, provisioned product."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel, _norm_arn


ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Launch"
PRODUCT = f"arn:aws:catalog:us-east-1:{ACCOUNT}:product/prod-123"
PORTFOLIO = f"arn:aws:catalog:us-east-1:{ACCOUNT}:portfolio/port-123"


def _proof(self_associate):
    return {
        "TechniqueId": ("aws-servicecatalog-associateprincipal-createartifact-provision" if self_associate
                        else "aws-servicecatalog-createprovisioningartifact-provisionproduct"),
        "SourceArn": SOURCE, "TargetKind": "aws_role", "TargetId": ROLE,
        "Status": "verified", "VerifiedPreconditions": True,
        "ProductArn": PRODUCT, "PortfolioArn": PORTFOLIO,
        "TargetRoleId": "AROA123456789", "LaunchConstraintRoleArn": ROLE,
        "ProductOwnedByAccount": True, "PortfolioContainsProduct": True,
        "TemplateControlledBySource": True, "ArtifactCreatedSucceeded": True,
        "TemplateAccepted": True, "ProvisionSucceeded": True,
        "LaunchConstraintApplied": True, "ArtifactId": "pa-123",
        "ProvisionedProductId": "pp-123",
        "SourceAlreadyPortfolioEndUser": not self_associate,
        "SourceAssociatedToPortfolio": self_associate,
        "SelfAssociationSucceeded": self_associate,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-servicecatalog-launch-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }


def _route(proof, *, self_associate=False, duplicates=False, source_has_action=False, deny=None):
    model = object.__new__(AwsModel)
    source = SimpleNamespace(id=SOURCE, scope=ACCOUNT)
    role = SimpleNamespace(id=ROLE, scope=ACCOUNT)
    rows = [deepcopy(proof)] * (2 if duplicates else 1)
    model.snapshot = {"created_at": "2026-10-22T12:00:00Z", "collections": [
        {"type": "iam_role", "scope": SCOPE, "status": "collected",
         "items": [{"Arn": ROLE, "RoleId": "AROA123456789"}]},
        {"type": "aws_privesc_challenge_evidence", "scope": SCOPE,
         "status": "collected", "items": rows},
    ]}
    key = (proof["TechniqueId"], SOURCE, "aws_role", ROLE)
    model.bounded_evidence_records = {key: [(SCOPE, row) for row in rows]}
    model.hosts = {ROLE: {"servicecatalog_product": [PRODUCT]}}
    model.sc_portfolios = {_norm_arn(ROLE): [PORTFOLIO]}
    grant = SimpleNamespace(confidence="derived")
    model._check_action = lambda principal, action, ref: None if action == deny else grant
    model.check = lambda principal, action, resource: (
        grant if principal is role or source_has_action else None)
    return model._servicecatalog_verified_artifact_role_effect(
        source, role, self_associate=self_associate)


def test_servicecatalog_route_requires_modified_provisioned_artifact():
    for self_associate in (False, True):
        proof = _proof(self_associate)
        assert _route(proof, self_associate=self_associate) == (
            "conditional", "servicecatalog_exact_launch_role_effect_verified")
        changes = [("ProductArn", PRODUCT.replace("prod-123", "prod-other")),
                   ("PortfolioArn", PORTFOLIO.replace("port-123", "port-other")),
                   ("TargetRoleId", "AROAOTHER"), ("ProductOwnedByAccount", False),
                   ("PortfolioContainsProduct", False), ("TemplateControlledBySource", False),
                   ("ArtifactCreatedSucceeded", False), ("ProvisionSucceeded", False),
                   ("LaunchConstraintApplied", False), ("RoleActionSucceeded", False),
                   ("EvidenceObservedAt", "2026-10-22T11:00:00Z")]
        changes.append(("SelfAssociationSucceeded", False) if self_associate else
                       ("SourceAlreadyPortfolioEndUser", False))
        for field, value in changes:
            changed = deepcopy(proof)
            changed[field] = value
            assert _route(changed, self_associate=self_associate)[0] == "unknown", field
        assert _route(proof, self_associate=self_associate, duplicates=True)[0] == "unknown"
        assert _route(proof, self_associate=self_associate,
                      deny="servicecatalog:ProvisionProduct")[0] == "unknown"
        assert _route(proof, self_associate=self_associate, source_has_action=True) is None
