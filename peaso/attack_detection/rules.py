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
from .aws_login_profile_next import normalize_aws_other_user_login_profile, normalize_aws_other_user_login_profile_update
from .aws_security_controls import normalize_aws_security_control
from .aws_trail_update import normalize_aws_trail_update
from .aws_role_boundary_next import normalize_aws_role_boundary_delete
from .aws_user_boundary_self_next import normalize_aws_self_user_boundary_delete
from .aws_wildcard_trust_next import normalize_aws_wildcard_role_trust
from .aws_keyspaces_next import normalize_keyspaces_other_user_credential
from .aws_s3_bucket import normalize_aws_s3_bucket
from .aws_sqs_queue import normalize_aws_sqs_queue
from .aws_sns_topic import normalize_aws_sns_topic
from .gcp import normalize_gcp_audit
from .gcp_next import normalize_gcp_project_self_iam_bindings
from .gcp_iam_cross_project_next import normalize_gcp_cross_project_sa_grants
from .gcp_logging_next import normalize_gcp_default_sink_disabled
from .gcp_logging_tamper_next import normalize_gcp_data_access_exclusion_created, normalize_gcp_data_access_log_delete
from .gcp_hmac_next import normalize_gcp_hmac_key_created
from .gcp_secret_versions_next import (
    normalize_gcp_secret_delete,
    normalize_gcp_secret_version_destroy,
    normalize_gcp_secret_version_disable,
)
from .kubernetes import normalize_kubernetes_audit_candidates
from .kubernetes_next import normalize_kubernetes_cluster_admin_grant
from .kubernetes_pod_next import normalize_kubernetes_privileged_host_pod
from .kubernetes_ephemeral_next import normalize_kubernetes_privileged_ephemeral_update
from .kubernetes_runtime_socket_next import normalize_kubernetes_runtime_socket_pod
from .kubernetes_aggregate_view_next import normalize_aggregate_view_secret_read
from .kubernetes_daemonset_next import normalize_kubernetes_privileged_daemonset


DEFAULT_RULE_REPO = "peass-ng/peasso-cspm-detections"
DEFAULT_RULE_REF = "81062edeae920123dd4cf3e1d304e7fa8b1b9fd7"
DEFAULT_RULE_PACK_SHA256 = "59c4359f609f40de4b732c64b773905a2363951d157c14886f3968a6280d007b"


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
        return tuple((path.relative_to(directory).as_posix(), path.read_text(encoding="utf-8"))
                     for path in sorted(directory.rglob("*.yml")))
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
            ("azure", "activity"), ("azure", "entra"),
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
    def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
        base = (normalize_aws_cloudtrail(record) or normalize_aws_security_control(record)
                or normalize_aws_trail_update(record))
        profile = normalize_aws_other_user_login_profile(record)
        updated_profile = normalize_aws_other_user_login_profile_update(record)
        boundary = normalize_aws_role_boundary_delete(record)
        self_user_boundary = normalize_aws_self_user_boundary_delete(record)
        trust = normalize_aws_wildcard_role_trust(record)
        keyspaces_credential = normalize_keyspaces_other_user_credential(record)
        s3_bucket = normalize_aws_s3_bucket(record)
        sqs_queue = normalize_aws_sqs_queue(record)
        sns_topic = normalize_aws_sns_topic(record)
        return (([base] if base is not None else [])
                + ([profile] if profile is not None else [])
                + ([updated_profile] if updated_profile is not None else [])
                + ([boundary] if boundary is not None else [])
                + ([self_user_boundary] if self_user_boundary is not None else [])
                + ([trust] if trust is not None else [])
                + ([keyspaces_credential] if keyspaces_credential is not None else [])
                + ([s3_bucket] if s3_bucket is not None else [])
                + ([sqs_queue] if sqs_queue is not None else [])
                + ([sns_topic] if sns_topic is not None else []))

    return _detect_events(records, rules if rules is not None else load_rules(product="aws"), normalize, "aws")


def detect_gcp_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Detect successful GCP audit events with concrete credential evidence."""
    def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
        base = normalize_gcp_audit(record)
        sink = normalize_gcp_default_sink_disabled(record)
        deleted = normalize_gcp_data_access_log_delete(record)
        exclusion = normalize_gcp_data_access_exclusion_created(record)
        hmac_key = normalize_gcp_hmac_key_created(record)
        destroyed = normalize_gcp_secret_version_destroy(record)
        disabled = normalize_gcp_secret_version_disable(record)
        secret_deleted = normalize_gcp_secret_delete(record)
        return (([base] if base is not None else [])
                + normalize_gcp_project_self_iam_bindings(record)
                + normalize_gcp_cross_project_sa_grants(record)
                + ([sink] if sink is not None else [])
                + ([deleted] if deleted is not None else [])
                + ([exclusion] if exclusion is not None else [])
                + ([hmac_key] if hmac_key is not None else [])
                + ([destroyed] if destroyed is not None else [])
                + ([disabled] if disabled is not None else [])
                + ([secret_deleted] if secret_deleted is not None else []))

    return _detect_events(records, rules if rules is not None else load_rules(product="gcp"), normalize, "gcp")


def detect_kubernetes_events(
    records: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Detect completed Kubernetes audit events with returned RBAC objects."""
    def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
        base = normalize_kubernetes_audit_candidates(record)
        next_event = normalize_kubernetes_cluster_admin_grant(record)
        pod = normalize_kubernetes_privileged_host_pod(record)
        ephemeral = normalize_kubernetes_privileged_ephemeral_update(record)
        socket = normalize_kubernetes_runtime_socket_pod(record)
        aggregate_view = normalize_aggregate_view_secret_read(record)
        daemonset = normalize_kubernetes_privileged_daemonset(record)
        return (base
                + ([next_event] if next_event is not None else [])
                + ([pod] if pod is not None else [])
                + ([ephemeral] if ephemeral is not None else [])
                + ([socket] if socket is not None else [])
                + ([aggregate_view] if aggregate_view is not None else [])
                + ([daemonset] if daemonset is not None else []))

    return _detect_events(records, rules if rules is not None else load_rules(product="kubernetes"), normalize, "kubernetes")


def detect_azure_events(
    correlated_events: Iterable[Mapping[str, Any]], rules: Sequence[Rule] | None = None,
) -> list[Detection]:
    """Match reviewed Sigma rules against bounded, joined Azure Activity evidence."""
    return _detect_events(correlated_events, rules if rules is not None else load_rules(product="azure"), lambda event: event, "azure")


def _detect_events(
    records: Iterable[Mapping[str, Any]], selected_rules: Sequence[Rule], normalizer: Any, product: str,
) -> list[Detection]:
    # Most packs contain many rules for a small set of event sources. Keep the
    # caller's rule order while considering only rules whose exact source/name
    # selectors can match this event. Rules without those selectors remain in
    # wildcard buckets and retain the same matching semantics.
    any_value = object()
    def exact(actual: Any, expected: Any) -> bool:
        # Python considers True == 1 and False == 0. Sigma scalar selectors
        # must not turn numeric telemetry into a boolean proof field.
        if isinstance(actual, bool) or isinstance(expected, bool):
            return type(actual) is type(expected) and actual == expected
        return actual == expected

    def index_value(value: Any) -> Any:
        try:
            hash(value)
        except TypeError:
            return any_value
        return value

    rules = [rule for rule in selected_rules if rule.product == product]
    buckets: dict[tuple[Any, Any], set[int]] = {}
    for index, rule in enumerate(rules):
        values = []
        for field in ("event.source", "event.name"):
            value = rule.selection.get(field, any_value)
            choices = value if isinstance(value, list) else [value]
            values.append([index_value(item) for item in choices])
        for source in values[0]:
            for name in values[1]:
                buckets.setdefault((source, name), set()).add(index)

    matches: list[Detection] = []
    for record in records:
        normalized = normalizer(record)
        events = [normalized] if isinstance(normalized, Mapping) else normalized or []
        for event in events:
            if not isinstance(event, Mapping):
                continue
            source = event.get("event.source")
            name = event.get("event.name")
            source = index_value(source)
            name = index_value(name)
            candidate_indexes: set[int] = set()
            for key in ((source, name), (source, any_value), (any_value, name), (any_value, any_value)):
                candidate_indexes.update(buckets.get(key, ()))
            for index in sorted(candidate_indexes):
                rule = rules[index]
                if all(any(exact(event.get(field), choice) for choice in expected)
                       if isinstance(expected, list) else exact(event.get(field), expected)
                       for field, expected in rule.selection.items()):
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
