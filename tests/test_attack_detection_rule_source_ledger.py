"""A rule source link must resolve in the same pinned corpus being counted."""

from pathlib import Path

from scripts.attack_detection_rule_source_ledger import build_ledger, source_page


REVISION = "a" * 40
PAGE = "aws-security/aws-privilege-escalation/example.md"
REFERENCE = (
    "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/"
    f"{REVISION}/src/pentesting-cloud/{PAGE}#L5"
)


def test_exact_revision_and_existing_page_are_required(tmp_path: Path):
    source = tmp_path / "corpus" / "src" / "pentesting-cloud"
    page = source / PAGE
    page.parent.mkdir(parents=True)
    page.write_text("# AWS privilege escalation\n\n## Attach administrator policy\n\n"
                    "An administrator policy can be attached to a principal.\n\n"
                    "```bash\naws iam attach-user-policy --user-name test --policy-arn arn:example\n```\n")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "exact.yml").write_text(
        "x_hacktricks_technique_id: attach-admin\n"
        "logsource: {product: aws}\n"
        f"references: ['{REFERENCE}']\n"
    )
    (rules / "stale.yml").write_text(
        "x_hacktricks_technique_id: stale\n"
        "logsource: {product: aws}\n"
        f"references: ['{REFERENCE.replace(REVISION, 'b' * 40)}']\n"
    )
    (rules / "missing.yml").write_text(
        "x_hacktricks_technique_id: missing\n"
        "logsource: {product: aws}\n"
        f"references: ['{REFERENCE.replace('example.md', 'absent.md')}']\n"
    )
    ledger = build_ledger(tmp_path / "corpus", rules, REVISION)
    assert ledger["rule_count"] == 3
    assert ledger["candidate_page_count"] == 1
    assert ledger["rule_referenced_candidate_page_count"] == 1
    assert ledger["rules_without_exact_source_page"] == ["stale.yml"]
    assert ledger["rules_with_missing_source_page"] == ["missing.yml"]


def test_rejects_cross_repo_and_path_traversal_links():
    assert source_page(REFERENCE, REVISION) == PAGE
    assert source_page(REFERENCE.replace(REVISION, "b" * 40), REVISION) is None
    assert source_page(REFERENCE.replace("HackTricks-wiki", "attacker"), REVISION) is None
    assert source_page(REFERENCE.replace("example.md", "../example.md"), REVISION) is None
