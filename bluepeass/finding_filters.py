"""Scoped, declarative exclusions for findings with known non-actionable cases."""

from collections import Counter
import copy
from fnmatch import fnmatchcase
from functools import lru_cache, wraps
from pathlib import Path

import yaml


BLACKLIST = Path(__file__).with_name("finding_blacklist.yaml")


@lru_cache(maxsize=1)
def blacklist_rules():
    document = yaml.safe_load(BLACKLIST.read_text())
    if document.get("version") != 1:
        raise ValueError("Unsupported finding blacklist version")
    rules = document.get("rules", [])
    seen = set()
    for rule in rules:
        if not all(rule.get(key) for key in ["id", "provider", "sections", "reason"]):
            raise ValueError("Finding blacklist rules need an id, provider, sections, and reason")
        if rule["id"] in seen or not (rule.get("identifier_patterns") or rule.get("control_patterns") or rule.get("attribute_patterns")):
            raise ValueError("Finding blacklist rules need unique IDs and explicit match conditions")
        seen.add(rule["id"])
        for key in ["sections", "identifier_patterns", "control_patterns", "statuses"]:
            if key in rule and (not isinstance(rule[key], list) or not all(isinstance(value, str) for value in rule[key])):
                raise ValueError("Finding blacklist match lists must contain strings")
        attributes = rule.get("attribute_patterns", {})
        if not isinstance(attributes, dict) or any(not isinstance(key, str) or not isinstance(values, list) or not values or not all(isinstance(value, str) for value in values) for key, values in attributes.items()):
            raise ValueError("Finding blacklist attributes need named string-pattern lists")
    return rules


def matching_rule(provider, section, identifier, *, control_id="", status=None, attributes=None, rules=None):
    provider = "kubernetes" if provider == "k8s" else provider
    for rule in blacklist_rules() if rules is None else rules:
        if rule["provider"] != provider or section not in rule["sections"]:
            continue
        if rule.get("identifier_patterns") and not any(fnmatchcase(str(identifier or ""), pattern) for pattern in rule["identifier_patterns"]):
            continue
        if rule.get("control_patterns") and not any(fnmatchcase(control_id, pattern) for pattern in rule["control_patterns"]):
            continue
        if rule.get("statuses") and status not in rule["statuses"]:
            continue
        matched = True
        for path, patterns in rule.get("attribute_patterns", {}).items():
            value = attributes or {}
            for part in path.split("."):
                if not isinstance(value, dict) or part not in value:
                    value = None
                    break
                value = value[part]
            if value is None or not any(fnmatchcase(str(value), pattern) for pattern in patterns):
                matched = False
                break
        if not matched:
            continue
        return rule
    return None


def _metadata(previous, counts, rules=None):
    by_rule = copy.deepcopy((previous or {}).get("by_rule", {}))
    definitions = {rule["id"]: rule for rule in (blacklist_rules() if rules is None else rules)}
    for identifier, count in counts.items():
        item = by_rule.setdefault(identifier, {"count": 0, "reason": definitions.get(identifier, {}).get("reason", "Explicit blacklist rule")})
        item["count"] += count
    return {"ruleset_version": 1, "suppressed": sum(item["count"] for item in by_rule.values()), "by_rule": by_rule}


def filter_aws_raw_report(raw):
    """Apply before the AWS console and normalization; keep actual grants/trusts."""
    result, counts = dict(raw), Counter()
    for field, section in [("unused_roles", "principals_inactive"), ("unused_custom_policies", "unused_custom_definitions"), ("unused_permissions", "principals_with_unused_permissions")]:
        if not isinstance(raw.get(field), dict):
            continue
        kept = {}
        for identifier, entry in raw[field].items():
            # Without Access Analyzer this dictionary contains flagged grants,
            # rather than evidence of unused permissions. Keep those grants.
            eligible = field != "unused_permissions" or (isinstance(entry, dict) and "last_perms" in entry)
            rule = matching_rule("aws", section, identifier) if eligible else None
            if rule:
                counts[rule["id"]] += 1
                if field == "unused_roles" and isinstance(entry, dict) and entry.get("permissions"):
                    # Legacy inputs may keep grant evidence only on the unused
                    # role entry. Preserve grants while removing its inactivity.
                    result["role_permissions"] = {**result.get("role_permissions", {}), identifier: entry["permissions"]}
                    result["retained_role_grants"] = {**result.get("retained_role_grants", {}), identifier: entry["permissions"]}
            else:
                kept[identifier] = entry
        result[field] = kept
    if counts or raw.get("finding_filters"):
        result["finding_filters"] = _metadata(raw.get("finding_filters"), counts)
    return result


def filter_raw_scope(raw, provider):
    if provider == "aws":
        return filter_aws_raw_report(raw)
    result, counts = dict(raw), Counter()
    source = raw.get("findings", {}) if provider in {"k8s", "kubernetes"} else raw
    filtered = dict(source)
    aliases = {"unused_custom_roles": "unused_custom_definitions", "inactive_principals": "principals_inactive"}
    for field, entries in source.items():
        if not isinstance(entries, list):
            continue
        section = aliases.get(field, field)
        kept = []
        for entry in entries:
            if not isinstance(entry, dict):
                kept.append(entry); continue
            if provider in {"k8s", "kubernetes"} and section == "unused_custom_definitions":
                identifier = f"{entry.get('kind')}/{entry.get('scope')}/{entry.get('name')}"
            elif section == "unused_custom_definitions":
                identifier = entry.get("role_definition_id") or entry.get("name") or entry.get("role")
            else:
                identifier = entry.get("principal_id") or entry.get("principal") or entry.get("member") or entry.get("name")
            rule = matching_rule(provider, section, identifier, attributes=entry)
            if rule:
                counts[rule["id"]] += 1
            else:
                kept.append(entry)
        filtered[field] = kept
    if provider in {"k8s", "kubernetes"}:
        result["findings"] = filtered
    else:
        result = filtered
    if counts or raw.get("finding_filters"):
        result["finding_filters"] = _metadata(raw.get("finding_filters"), counts)
    return result


def print_filter_summary(data):
    metadata = data.get("finding_filters") or {}
    if metadata.get("suppressed"):
        rules = ", ".join(f"{rule}={item['count']}" for rule, item in metadata["by_rule"].items())
        print(f"Known non-actionable finding records suppressed: {metadata['suppressed']} ({rules})")


def filter_normalized_findings(data, provider):
    findings = data.get("findings")
    if not isinstance(findings, dict):
        return data
    catalogs = {name: {str(item.get("id")): item for item in (findings.get(name) or []) if isinstance(item, dict)} for name in ["principal_catalog", "group_catalog", "role_catalog"]}
    result, kept_findings, counts = dict(data), dict(findings), Counter()
    for section, entries in findings.items():
        if section not in {s for rule in blacklist_rules() if rule["provider"] == ("kubernetes" if provider == "k8s" else provider) for s in rule["sections"]} or not isinstance(entries, list):
            continue
        kept = []
        for entry in entries:
            if not isinstance(entry, dict):
                kept.append(entry); continue
            if "definition_ref" in entry:
                referenced = catalogs["role_catalog"].get(str(entry["definition_ref"]), {})
            else:
                catalog = "group_catalog" if entry.get("subject_kind") == "group" else "principal_catalog"
                referenced = catalogs[catalog].get(str(entry.get("subject_ref")), {})
            identifier = referenced.get("identifier") or referenced.get("label") or entry.get("principal_id") or entry.get("role_definition_id")
            rule = matching_rule(provider, section, identifier, attributes={**entry, **referenced})
            if rule:
                counts[rule["id"]] += 1
            else:
                kept.append(entry)
        kept_findings[section] = kept
    result["findings"] = kept_findings
    if counts or data.get("finding_filters"):
        result["finding_filters"] = _metadata(data.get("finding_filters"), counts)
    return result


def filter_hardening_audit(audit, provider, *, rules=None):
    result, kept, counts = dict(audit), [], Counter()
    for finding in audit.get("findings", []):
        # Query errors always remain visible, even with a broad custom rule.
        rule = None if finding.get("status") == "ERROR" else matching_rule(provider, "hardening", finding.get("resource"), control_id=finding.get("control_id", ""), status=finding.get("status"), attributes=finding, rules=rules)
        if rule:
            counts[rule["id"]] += 1
        else:
            kept.append(finding)
    result["findings"] = kept
    if counts or audit.get("finding_filters"):
        result["finding_filters"] = _metadata(audit.get("finding_filters"), counts, rules)
        statuses = Counter(finding.get("status", "UNKNOWN") for finding in kept)
        result["summary"] = {**audit.get("summary", {}), "findings": len(kept), "by_status": dict(statuses)}
    return result


def aggregate_filter_metadata(items):
    by_rule = {}
    for metadata in items:
        for identifier, item in (metadata or {}).get("by_rule", {}).items():
            combined = by_rule.setdefault(identifier, {"count": 0, "reason": item["reason"]})
            combined["count"] += item["count"]
    return {"ruleset_version": 1, "suppressed": sum(item["count"] for item in by_rule.values()), "by_rule": by_rule}


def filtered_normalizer(provider):
    """Keep provider raw data and its catalog-based findings consistent."""
    def decorate(normalizer):
        @wraps(normalizer)
        def normalize(raw):
            prepared = filter_raw_scope(raw, provider)
            result = normalizer(prepared)
            metadata = prepared.get("finding_filters") or (prepared.get("stats") or {}).get("finding_filters")
            if metadata:
                result["finding_filters"] = metadata
            return filter_normalized_findings(result, provider)
        return normalize
    return decorate
