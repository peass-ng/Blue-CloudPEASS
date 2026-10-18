"""Evaluate a deliberately small, portable subset of Sigma against canonical events.

The checked-in YAML follows Sigma's logsource/detection/condition format. This
module supports only exact field equality, OR lists, AND within one selection,
and ``condition: selection``. Unsupported constructs fail closed at load time.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
import os
from pathlib import Path
from typing import Any

import yaml

from .aws import normalize_aws_cloudtrail
from .aws_security_controls import normalize_aws_security_control
from .gcp import normalize_gcp_audit
from .kubernetes import normalize_kubernetes_audit


DEFAULT_RULE_REPO = "peass-ng/hacktricks-cspm-detections"
DEFAULT_RULE_REF = "7395af98c1088b70959a9552dd28dbd0832a8b51"
DEFAULT_RULE_PACK_SHA256 = "9f0785d135b5ae84b764bae504c96800846718152e5a1f3d5808cbdae935d9f5"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    level: str
    description: str
    technique_id: str
    product: str
    selection: Mapping[str, Any]
    falsepositives: tuple[str, ...] = ()


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    technique_id: str
    event_id: str | None
    event_time: str | None
    account_id: str | None
    actor_id: str | None
    target_id: str | None
    evidence: Mapping[str, Any]
    description: str
    legitimate_context: tuple[str, ...]


class RuleSourceError(ValueError):
    """A stable error that never contains the GitHub credential or response."""


@lru_cache(maxsize=4)
def _github_rule_texts(repo: str, ref: str) -> tuple[tuple[str, str], ...]:
    if not repo or not ref:
        raise RuleSourceError("rule_source_not_configured")
    try:
        from .github_source import fetch_rules
        digest = (DEFAULT_RULE_PACK_SHA256 if (repo, ref) == (DEFAULT_RULE_REPO, DEFAULT_RULE_REF)
                  else os.getenv("HACKTRICKS_CSPM_RULES_PACK_SHA256") or None)
        return tuple(sorted(fetch_rules(repo, ref, digest).items()))
    except Exception:
        raise RuleSourceError("rule_source_unavailable") from None


def _rule_texts(directory: Path | None) -> tuple[tuple[str, str], ...]:
    if directory is not None:
        return tuple((path.name, path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.yml")))
    repo_override = os.getenv("HACKTRICKS_CSPM_RULES_GITHUB_REPO", "")
    ref_override = os.getenv("HACKTRICKS_CSPM_RULES_GITHUB_REF", "")
    local = os.getenv("HACKTRICKS_CSPM_RULES_DIR", "")
    if local and os.getenv("PEASO_AUTH_MODE") != "cognito" and not repo_override and not ref_override:
        return _rule_texts(Path(local))
    if repo_override and not ref_override:
        raise RuleSourceError("rule_source_ref_required")
    return _github_rule_texts(repo_override or DEFAULT_RULE_REPO, ref_override or DEFAULT_RULE_REF)


def load_rules(directory: Path | None = None, *, product: str | None = None) -> tuple[Rule, ...]:
    loaded: list[Rule] = []
    for name, text in _rule_texts(directory):
        source = yaml.safe_load(text)
        if not isinstance(source, Mapping):
            raise ValueError(f"Invalid detection rule: {name}")
        logsource = source.get("logsource")
        detection = source.get("detection")
        if not isinstance(logsource, Mapping) or (logsource.get("product"), logsource.get("service")) not in {
            ("aws", "cloudtrail"), ("gcp", "audit"), ("kubernetes", "audit"),
            ("azure", "activity"),
        } or set(logsource) != {"product", "service"}:
            raise ValueError(f"Unsupported log source: {name}")
        if not isinstance(detection, Mapping) or set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
            raise ValueError(f"Unsupported detection grammar: {name}")
        selection = detection["selection"]
        if not isinstance(selection, Mapping) or not selection or any(not isinstance(k, str) or "|" in k for k in selection):
            raise ValueError(f"Unsupported detection selection: {name}")
        if any(not isinstance(v, (str, bool, int, list)) or isinstance(v, list) and (not v or any(not isinstance(x, (str, bool, int)) for x in v)) for v in selection.values()):
            raise ValueError(f"Unsupported detection values: {name}")
        if product is not None and logsource["product"] != product:
            continue
        falsepositives = source.get("falsepositives", [])
        if (not isinstance(falsepositives, list) or len(falsepositives) > 10
                or any(not isinstance(item, str) or not item or len(item) > 500 for item in falsepositives)):
            raise ValueError(f"Invalid legitimate context: {name}")
        loaded.append(Rule(
            id=str(source["id"]), title=str(source["title"]),
            level=str(source["level"]), description=str(source["description"]),
            technique_id=str(source["x_hacktricks_technique_id"]),
            product=logsource["product"],
            selection=dict(selection),
            falsepositives=tuple(falsepositives),
        ))
    if not loaded:
        raise ValueError("No detection rules found")
    if len({rule.id for rule in loaded}) != len(loaded):
        raise ValueError("Duplicate detection rule ID")
    return tuple(loaded)


def detect_aws_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Return evidence for matching records; no compromise verdict is implied."""
    def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
        return normalize_aws_cloudtrail(record) or normalize_aws_security_control(record)

    return _detect_events(records, rules if rules is not None else load_rules(product="aws"), normalize, "aws")


def detect_gcp_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Detect successful GCP audit events with concrete credential evidence."""
    return _detect_events(records, rules if rules is not None else load_rules(product="gcp"), normalize_gcp_audit, "gcp")


def detect_kubernetes_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Detect completed Kubernetes audit events with returned RBAC objects."""
    return _detect_events(records, rules if rules is not None else load_rules(product="kubernetes"), normalize_kubernetes_audit, "kubernetes")


def detect_azure_events(
    correlated_events: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Match reviewed Sigma rules against bounded, joined Azure Activity evidence."""
    return _detect_events(correlated_events, rules if rules is not None else load_rules(product="azure"), lambda event: event, "azure")


def _detect_events(
    records: Iterable[Mapping[str, Any]], selected_rules: Sequence[Rule], normalizer: Any, product: str,
) -> list[Detection]:
    matches: list[Detection] = []
    for record in records:
        event = normalizer(record)
        if event is None:
            continue
        for rule in selected_rules:
            if rule.product != product:
                continue
            if all(event.get(field) in expected if isinstance(expected, list) else event.get(field) == expected for field, expected in rule.selection.items()):
                evidence = {field: event[field] for field in rule.selection}
                correlation = event.get("correlation_evidence")
                if isinstance(correlation, Mapping):
                    evidence["correlation"] = dict(correlation)
                matches.append(Detection(
                    rule_id=rule.id, title=rule.title, severity=rule.level,
                    technique_id=rule.technique_id,
                    event_id=event["event.id"], event_time=event["event.time"],
                    account_id=event["account.id"],
                    actor_id=event["actor.id"], target_id=event["target.id"],
                    evidence=evidence,
                    description=rule.description,
                    legitimate_context=rule.falsepositives,
                ))
    return matches
