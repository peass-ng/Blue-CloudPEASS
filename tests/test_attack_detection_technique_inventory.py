"""Deterministic and explicitly heuristic HackTricks section inventory."""
from __future__ import annotations

import json

import pytest

from scripts.attack_detection_technique_inventory import build_inventory


REVISION = "f" * 40


def _page(root, provider, relative, text):
    path = root / "src" / "pentesting-cloud" / provider / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_path_and_heading_categories_commands_and_duplicate_titles(tmp_path):
    _page(tmp_path, "aws-security", "aws-privilege-escalation/iam.md", """
# AWS IAM
## IAM
### Attach admin policy
This section describes a permission change that might be made by an administrator during normal work, and needs investigation in context.
```bash
USER=example
aws iam attach-user-policy --user-name "$USER" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```
### Attach admin policy
```shell
aws iam put-user-policy --user-name example --policy-name admin --policy-document file://policy.json
```
### References
See a long list of references that should never count as an attack technique section even if it contains a command.
```bash
aws iam list-users
```
```bash
# ### This fenced title is not a Markdown heading.
```
""")
    _page(tmp_path, "gcp-security", "gcp-services/iam.md", """
# GCP IAM
## Enumeration
### List service accounts
```bash
gcloud iam service-accounts list --project=demo-project
```
""")
    _page(tmp_path, "azure-security", "az-persistence/token.md", """
# Azure token
## Reusable credentials
This candidate has enough direct prose to be listed, but the inventory cannot conclude from prose whether this is an attack or whether there is an audit-log signal for it.
""")
    _page(tmp_path, "kubernetes-security", "kubernetes-post-exploitation/rbac.md", """
# Kubernetes
## RBAC
### Create a binding
```console
$ kubectl create clusterrolebinding example --clusterrole=cluster-admin --serviceaccount=demo:runner
```
""")
    inventory = build_inventory(tmp_path, source_revision=REVISION)
    counts = inventory["counts"]
    assert counts["candidate_sections"] == 5
    assert counts["pages_with_candidates"] == 4
    assert counts["sections_with_commands"] == 4
    assert counts["by_provider_category"]["aws"]["privilege_escalation"] == 2
    assert counts["by_provider_category"]["gcp"]["enumeration"] == 1
    assert counts["by_provider_category"]["azure"]["persistence"] == 1
    assert counts["by_provider_category"]["k8s"]["post_exploitation"] == 1
    aws = [row for row in inventory["sections"] if row["provider"] == "aws"]
    assert aws[0]["id"].endswith("#attach-admin-policy")
    assert aws[1]["id"].endswith("#attach-admin-policy-2")
    assert aws[0]["command_count"] == 1
    assert aws[0]["command_examples"][0].startswith("aws iam attach-user-policy")
    assert "References" not in [row["heading"] for row in inventory["sections"]]


def test_repeatable_and_capped_command_examples(tmp_path):
    _page(tmp_path, "gcp-security", "gcp-persistence/keys.md", "# GCP\n## Upload key\n```bash\n" +
          "\n".join(f"gcloud iam service-accounts keys upload key-{i}.pem" for i in range(8)) + "\n```\n")
    first = build_inventory(tmp_path)
    second = build_inventory(tmp_path)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    section = first["sections"][0]
    assert section["command_count"] == 8
    assert len(section["command_examples"]) == 5
    assert section["command_examples_truncated"] is True
    assert first["source_revision"] is None


def test_invalid_root_and_revision_fail_closed(tmp_path):
    with pytest.raises(ValueError, match="corpus_root_missing_provider_directories"):
        build_inventory(tmp_path)
    _page(tmp_path, "aws-security", "aws-persistence/iam.md", "# IAM\n## Key\n```bash\naws iam list-users\n```\n")
    with pytest.raises(ValueError, match="source_revision_must_be_full_git_sha"):
        build_inventory(tmp_path, source_revision="main")
