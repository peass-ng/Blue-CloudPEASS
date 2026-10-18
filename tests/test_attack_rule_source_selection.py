"""Hosted detection content must come from the pinned GitHub source."""

from __future__ import annotations

import pytest

from peaso.attack_detection.rules import (
    DEFAULT_RULE_REF, DEFAULT_RULE_REPO, RuleSourceError, _github_rule_texts, load_rules,
)


SAMPLE = """id: test-rule
title: Synthetic event
level: low
description: Test only
x_hacktricks_technique_id: synthetic
logsource: {product: aws, service: cloudtrail}
detection:
  selection: {event.name: SyntheticAction}
  condition: selection
"""


def test_hosted_rule_source_never_uses_local_directory(monkeypatch, tmp_path):
    import peaso.attack_detection.github_source as source
    (tmp_path / "sample.yml").write_text(SAMPLE, encoding="utf-8")
    monkeypatch.setenv("HACKTRICKS_CSPM_RULES_DIR", str(tmp_path))
    monkeypatch.setenv("PEASO_AUTH_MODE", "cognito")
    for name in ("HACKTRICKS_CSPM_RULES_GITHUB_REPO", "HACKTRICKS_CSPM_RULES_GITHUB_REF"):
        monkeypatch.delenv(name, raising=False)
    calls = []
    monkeypatch.setattr(source, "fetch_rules", lambda repo, ref, digest: calls.append((repo, ref)) or {"remote.yml": SAMPLE})
    _github_rule_texts.cache_clear()
    assert len(load_rules(product="aws")) == 1
    assert calls == [(DEFAULT_RULE_REPO, DEFAULT_RULE_REF)]
    assert len(load_rules(tmp_path, product="aws")) == 1
    monkeypatch.setenv("HACKTRICKS_CSPM_RULES_GITHUB_REPO", "other/public")
    with pytest.raises(RuleSourceError, match="rule_source_ref_required"):
        load_rules(product="aws")


def test_pinned_source_reads_public_repo_and_sanitizes_failures(monkeypatch):
    import peaso.attack_detection.github_source as source

    _github_rule_texts.cache_clear()
    monkeypatch.setattr(source, "fetch_rules", lambda repo, ref, digest: {"sample.yml": SAMPLE}
                        if (repo, ref) == ("owner/public", "a" * 40) else {})
    assert len(_github_rule_texts("owner/public", "a" * 40)) == 1
    _github_rule_texts.cache_clear()
    def denied(*args, **kwargs):
        raise RuntimeError("provider response should not be shown")
    monkeypatch.setattr(source, "fetch_rules", denied)
    with pytest.raises(RuleSourceError) as exc:
        _github_rule_texts("owner/public", "a" * 40)
    assert str(exc.value) == "rule_source_unavailable"
    assert "provider response" not in str(exc.value)


def test_local_rule_source_reads_provider_and_service_directories(tmp_path):
    nested = tmp_path / "aws" / "iam"
    nested.mkdir(parents=True)
    (nested / "sample.yml").write_text(SAMPLE, encoding="utf-8")
    rules = load_rules(tmp_path, product="aws")
    assert [rule.id for rule in rules] == ["test-rule"]
