"""Inventory unused-IAM control gaps without importing the native registry.

A candidate is a review lead, never proof of collector/runtime coverage. In
particular, archived controls and least-privilege-only controls cannot satisfy a
requirement to report in Hardening. This command deliberately has no 'covered'
verdict: collector provenance and evaluator behavior require separate tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

# Object families are explicit so an existing service-account check cannot hide
# missing users, group memberships, API credentials or authorization objects.
REQUIREMENTS = {
    "aws": {
        "users": "user|credential",
        "console_passwords": "console|password|credential",
        "access_keys": "access.?key|credential",
        "roles": "role",
        "groups": "group",
        "managed_policies": "policy",
        "inline_policies": "inline",
        "unused_services_and_actions": "access.*not_stale|unused.*permission|analyzer.*finding",
        "federation_and_identity_center_assignments": "federat|identity.center|sso",
        "service_specific_credentials": "service.specific|signing.certificate|ssh.*key",
    },
    "gcp": {
        "users": "user",
        "service_accounts": "service.account",
        "service_account_keys": "service_account_key",
        "api_keys": "api.?key",
        "groups_and_memberships": "group|membership",
        "custom_roles": "custom.*role",
        "iam_bindings_and_permissions": "binding|permission|recommender",
        "workload_and_workforce_federation": "workload.*identity|workforce|federat",
        "hmac_keys": "hmac",
    },
    "azure": {
        "users": "user",
        "groups_and_memberships": "group|membership",
        "service_principals": "service.principal|enterprise.*app",
        "application_registrations": "application|app.registration",
        "application_secrets_and_certificates": "credential|certificate|secret",
        "managed_identities": "managed.identity",
        "custom_roles": "custom.*role",
        "role_assignments_and_permissions": "role.assignment|permission|entitlement",
        "federated_identity_credentials": "federat",
        "api_and_service_access_keys": "api.?key|access.?key",
    },
    "k8s": {
        "service_accounts": "service.?account",
        "legacy_service_account_tokens": "legacy.*token|service.account.*token",
        "roles": "role",
        "cluster_roles": "cluster.?role",
        "role_bindings": "role.?binding",
        "cluster_role_bindings": "cluster.?role.?binding",
        "users_groups_and_client_certificates": "user|group|client.*cert",
        "rbac_permissions": "permission|rbac",
        "workload_identity_bindings": "workload.identity|federat",
    },
}
LIFECYCLE = re.compile(
    r"unused|inactive|orphan|unreferenced|unattached|recently.used|recent.sign.in|"
    r"not.stale|policy_in_use|group_not_empty|last.used|last.authenticated|used_within|has_declared_consumers|subjects_exist|recent_activity|has_members|have_members|has_consumer|has_observed_permission_use|recent_recorded_login|has_enabled_provider|recent_recorded_successful_requests|has_declared_grants", re.I)


# Prevent 'user-managed key' text from masquerading as a user-account control.
# These type restrictions narrow review leads; they never certify coverage.
EXACT_TYPES = {
    ('aws', 'users'): {'iam_user', 'iam_credential_report'},
    ('aws', 'console_passwords'): {'iam_user', 'iam_credential_report'},
    ('aws', 'access_keys'): {'iam_user', 'iam_credential_report', 'iam_access_key'},
    ('aws', 'roles'): {'iam_role'},
    ('aws', 'groups'): {'iam_group'},
    ('aws', 'managed_policies'): {'iam_policy'},
    ('aws', 'inline_policies'): {'iam_group', 'iam_user', 'iam_role'},
    ('gcp', 'users'): {'iam_user', 'directory_user', 'workspace_user'},
    ('gcp', 'service_accounts'): {'service_account'},
    ('gcp', 'service_account_keys'): {'service_account_key'},
    ('gcp', 'api_keys'): {'api_key'},
    ('gcp', 'groups_and_memberships'): {'directory_group', 'group', 'cloudidentity_group'},
    ('gcp', 'hmac_keys'): {'hmac_key', 'storage_hmac_key'},
    ('azure', 'users'): {'directory_user'},
    ('azure', 'groups_and_memberships'): {'directory_group'},
    ('azure', 'service_principals'): {'directory_service_principal'},
    ('azure', 'application_registrations'): {'directory_application'},
    ('azure', 'managed_identities'): {'managed_identity', 'user_assigned_identity', 'directory_service_principal'},
    ('k8s', 'service_accounts'): {'serviceaccount'},
    ('k8s', 'legacy_service_account_tokens'): {'secret_metadata'},
    ('k8s', 'roles'): {'role'},
    ('k8s', 'cluster_roles'): {'clusterrole'},
    ('k8s', 'role_bindings'): {'rolebinding'},
    ('k8s', 'cluster_role_bindings'): {'clusterrolebinding'},
}

def audit(catalog: dict) -> dict:
    active = catalog["checks"]
    archived = catalog.get("archived_checks", [])
    requirements = []
    for provider, families in REQUIREMENTS.items():
        for family, pattern in families.items():
            object_match = re.compile(pattern, re.I)
            def matches(row):
                text = " ".join(str(row.get(key, "")) for key in ("id", "title", "type"))
                explicit = provider == 'azure' and family == 'managed_identities' and row.get('id') == 'azure.iam.service_principal_recent_activity'
                allowed = EXACT_TYPES.get((provider, family))
                return (row.get("provider") == provider and (allowed is None or row.get("type") in allowed)
                        and bool(LIFECYCLE.search(text)) and (bool(object_match.search(text)) or explicit))
            current = [row for row in active if matches(row)]
            old = [row["id"] for row in archived if matches(row)]
            candidates = [{"id": row["id"], "category": row["category"],
                           "hacktricks": "HackTricks Cloud Best Practices" in row.get("frameworks", []),
                           "other_frameworks": [f for f in row.get("frameworks", []) if f != "HackTricks Cloud Best Practices"]}
                          for row in current]
            eligible = [row for row in candidates if row["category"] == "hardening" and row["hacktricks"]]
            state = ("runtime_and_evidence_review_required" if eligible else
                     "hardening_or_compliance_mapping_missing" if current else
                     "archived_only" if old else "no_candidate")
            requirements.append({"provider": provider, "object_family": family, "state": state,
                                 "candidates": candidates, "archived_candidates": old})
    return {"schema_version": 1, "scope": "unused IAM objects in AWS, GCP, Azure and Kubernetes",
            "candidate_matching_is_not_coverage_proof": True,
            "native_catalog_controls": len(active), "requirements": requirements}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path(__file__).resolve().parents[1] / "peaso/rulepacks/native_catalog.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = args.catalog.read_bytes()
    report = audit(json.loads(raw))
    report["catalog_sha256"] = hashlib.sha256(raw).hexdigest()
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
