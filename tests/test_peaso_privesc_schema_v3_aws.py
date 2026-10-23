"""The old untyped AWS challenge paths are retained only as history."""

from peaso.privesc.schema import load_catalog
from peaso.privesc.versioned_catalog import _verified_prior


UNTYPED = {
    "aws-v3-01-substitute-an-as2-partner-signing-certificate",
    "aws-v3-59-anonymous-cognito-guest-role",
}


def test_untyped_challenge_paths_are_archived_not_active():
    active = {entry["id"]: entry for entry in load_catalog(strict=True)["entries"]}
    prior, _ = _verified_prior()
    assert UNTYPED <= set(prior)
    assert not UNTYPED & set(active)
    for entry in active.values():
        if entry["provider"] != "aws" or entry["target"]["kind"] != "aws_verified_authority":
            continue
        selector = entry["target"]["selector"]
        if entry["id"] == "aws-deadline-passrole-fleet-createworker":
            assert entry["target"]["outcome"] == "bounded_authority"
            assert selector == {"aws_challenge_fact": entry["id"]}
            assert entry["target"]["grants"] == ["One observed Deadline worker operation on the exact worker"]
        else:
            assert entry["target"]["outcome"] == "permission_grant"
            assert "aws_challenge_fact" not in selector
            reviewed = ("aws_dynamodb_policy_self_grant", "aws_s3_policy_self_grant",
                        "aws_s3_access_grants_self_grant", "aws_scheduler_iam_self_grant",
                        "aws_scheduler_iam_self_grant_update", "aws_secretsmanager_policy_self_grant",
                        "aws_efs_policy_self_grant", "aws_cases_tag_self_grant",
                        "aws_sitewise_portal_self_grant", "aws_sns_policy_self_grant",
                        "aws_sqs_policy_self_grant")
            assert sum(bool(selector.get(key)) for key in reviewed) == 1, entry["id"]


def test_remaining_aws_credential_reads_use_exact_user_evidence():
    active = {entry["id"]: entry for entry in load_catalog(strict=True)["entries"]}
    for technique in ("aws-apprunner-plaintext-credential", "aws-lambda-getconfig-secret-identity"):
        entry = active[technique]
        assert entry["target"]["kind"] == "aws_user"
        assert "aws_challenge_fact" in str(entry["target"]["selector"])
        assert "review" in str(entry.get("conditions", [])).lower()
