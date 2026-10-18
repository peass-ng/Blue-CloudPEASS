"""Hosted detection content must come from the pinned private source."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from peaso.attack_detection.rules import RuleSourceError, _github_rule_texts, load_rules


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
    (tmp_path / "sample.yml").write_text(SAMPLE, encoding="utf-8")
    monkeypatch.setenv("HACKTRICKS_CSPM_RULES_DIR", str(tmp_path))
    monkeypatch.setenv("PEASO_AUTH_MODE", "cognito")
    for name in ("HACKTRICKS_CSPM_RULES_GITHUB_REPO", "HACKTRICKS_CSPM_RULES_GITHUB_REF",
                 "HACKTRICKS_CSPM_RULES_GITHUB_TOKEN_SECRET_ARN"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuleSourceError, match="private_rule_source_not_configured"):
        load_rules(product="aws")
    assert len(load_rules(tmp_path, product="aws")) == 1


def test_private_source_reads_secret_and_sanitizes_failures(monkeypatch):
    import boto3
    import peaso.attack_detection.github_source as source

    _github_rule_texts.cache_clear()
    fake = SimpleNamespace(get_secret_value=lambda **kwargs: {"SecretString": "private-token"})
    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: fake)
    monkeypatch.setattr(source, "fetch_rules", lambda repo, ref, token: {"sample.yml": SAMPLE}
                        if (repo, ref, token) == ("owner/private", "a" * 40, "private-token") else {})
    assert len(_github_rule_texts("owner/private", "a" * 40, "secret-arn")) == 1
    _github_rule_texts.cache_clear()
    def denied(*args, **kwargs):
        raise RuntimeError("private-token")
    monkeypatch.setattr(boto3, "client", denied)
    with pytest.raises(RuleSourceError) as exc:
        _github_rule_texts("owner/private", "a" * 40, "secret-arn")
    assert str(exc.value) == "private_rule_source_unavailable"
    assert "private-token" not in str(exc.value)
