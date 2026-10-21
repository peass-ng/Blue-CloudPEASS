"""The optional main catalog is resolved once and replayed by immutable digest."""

from __future__ import annotations

import io
import json

import pytest

from peaso.attack_detection import catalog, github_source
from peaso.attack_detection.rules import RuleSourceError


SAMPLE = """id: sample-aws-rule
title: Synthetic action
level: low
description: Test-only event.
x_hacktricks_technique_id: synthetic
logsource: {product: aws, service: cloudtrail}
detection:
  selection: {event.name: SyntheticAction}
  condition: selection
"""


def test_latest_catalog_uses_exact_resolved_commit_for_the_run(monkeypatch):
    first, second = "a" * 40, "b" * 40
    resolved = [first]
    fetched = []
    monkeypatch.setattr(catalog, "resolve_main_commit", lambda repo: resolved[0])
    monkeypatch.setattr(catalog, "fetch_rules", lambda repo, commit, digest: (
        fetched.append((repo, commit, digest)) or {"aws/iam/sample.yml": SAMPLE}))
    catalog._remote_catalog.cache_clear()
    checked = catalog.select_catalog("latest", product="aws")
    resolved[0] = second
    run = catalog.select_catalog("latest", product="aws", commit=checked.commit,
                                 digest=checked.sha256)
    assert checked.commit == run.commit == first
    assert checked.sha256 == run.sha256
    assert len(run.rules) == 1
    assert fetched[-1] == (catalog.DEFAULT_RULE_REPO, first, checked.sha256)


def test_latest_catalog_rejects_changed_or_invalid_pack(monkeypatch):
    monkeypatch.setattr(catalog, "fetch_rules", lambda repo, commit, digest: {
        "aws/iam/sample.yml": SAMPLE})
    catalog._remote_catalog.cache_clear()
    with pytest.raises(RuleSourceError, match="invalid_rule_catalog_commit"):
        catalog.select_catalog("latest", commit="main")
    with pytest.raises(RuleSourceError, match="rule_catalog_changed"):
        catalog.select_catalog("latest", commit="a" * 40, digest="0" * 64)
    monkeypatch.setattr(catalog, "fetch_rules", lambda repo, commit, digest: {
        "aws/iam/sample.yml": "id: malformed\n"})
    catalog._remote_catalog.cache_clear()
    with pytest.raises(RuleSourceError, match="rule_source_unavailable"):
        catalog.select_catalog("latest", commit="b" * 40)


def test_main_ref_resolution_is_bounded_and_validated(monkeypatch):
    class Response(io.BytesIO):
        status = 200

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://api.github.com/repos/peass-ng/peasso-cspm-detections/branches/main"
            assert timeout == 15
            return Response(json.dumps({"commit": {"sha": "A" * 40}}).encode())

    monkeypatch.setattr(github_source, "build_opener", lambda *args: Opener())
    assert github_source.resolve_main_commit("peass-ng/peasso-cspm-detections") == "a" * 40
    with pytest.raises(github_source.RuleSourceError, match="invalid_repo"):
        github_source.resolve_main_commit("https://other.example/rules")
