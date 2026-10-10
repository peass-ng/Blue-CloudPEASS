"""ECR tag/lifecycle/scanning metadata policies without image or credential access."""
import json
from fnmatch import fnmatchcase
from . import result, unknown
from .facts import get, list_of_objects, complete_items
from .aws_b_core import install


@install("aws.b.ecr.all_tags_immutable", "ecr_repository", "ECR repository makes all image tags immutable without mutable exclusions", {"imageTagMutability": "IMMUTABLE"}, {"imageTagMutability": "IMMUTABLE_WITH_EXCLUSION", "imageTagMutabilityExclusionFilters": [{"filterType": "WILDCARD", "filter": "development-*"}]}, query="ecr_repository_tag_immutability_enabled")
def immutable_tags(item, index):
    mode = get(item, "imageTagMutability", str)
    if mode not in {"MUTABLE", "IMMUTABLE", "IMMUTABLE_WITH_EXCLUSION", "MUTABLE_WITH_EXCLUSION"}:
        return unknown("unknown mutability mode", configured=mode)
    return result(mode != "IMMUTABLE", image_tag_mutability=mode, exclusion_filters=item.get("imageTagMutabilityExclusionFilters", []), semantics="Exact full-immutability source predicate; exclusion modes are preserved rather than normalized to booleans.")


@install("aws.b.ecr.lifecycle_rules", "ecr_repository", "ECR repository has lifecycle rule metadata", {"LifecyclePolicy": {"lifecyclePolicyText": '{"rules":[{"rulePriority":1}]}'}}, {"LifecyclePolicy": {"collection_status": "empty", "absent": True}}, query="ecr_repository_lifecycle_policy_configured")
def lifecycle(item, index):
    policy = get(item, "LifecyclePolicy", dict)
    if policy.get("collection_status") == "empty" and policy.get("absent") is True:
        return result(True, lifecycle_policy="absent")
    text = get(policy, "lifecyclePolicyText", str)
    data = json.loads(text)
    if not isinstance(data, dict):
        return unknown("malformed lifecycle policy object")
    rules = data.get("rules")
    if rules is not None:
        list_of_objects(rules)
    return result(rules is None, lifecycle_rules=rules, semantics="Pinned source rule-metadata presence; retention sizing and resulting deletions require separate review.")


_GOOD_REGISTRY = {"collections": {"ecr_registry_scanning_configuration": [{"status": "collected"}]}, "ecr_registry_scanning_configuration": [{"data": {"registryId": "111111111111", "scanningConfiguration": {"scanType": "ENHANCED", "rules": [{"scanFrequency": "CONTINUOUS_SCAN", "repositoryFilters": [{"filterType": "WILDCARD", "filter": "production-*"}]}]}}}]}
@install("aws.b.ecr.effective_scan_configuration", "ecr_repository", "ECR repository has scan-on-push or a matching enhanced scanning rule", {"repositoryName": "production-app", "imageScanningConfiguration": {"scanOnPush": False}}, {"repositoryName": "development-app", "imageScanningConfiguration": {"scanOnPush": False}}, query="_corrected:ecr_repository_image_scan_on_push_enabled", dependencies=["ecr_repository", "ecr_registry_scanning_configuration"], extra={"index": _GOOD_REGISTRY})
def scanning(item, index):
    pushed = get(item, "imageScanningConfiguration.scanOnPush", bool)
    name = get(item, "repositoryName", str)
    registry = complete_items(index, "ecr_registry_scanning_configuration")
    if len(registry) != 1:
        return unknown("registry scanning configuration not uniquely resolved")
    configuration = get(registry[0], "scanningConfiguration", dict)
    mode = get(configuration, "scanType", str)
    if mode == "BASIC":
        return result(not pushed, scan_on_push=pushed, registry_scan_type=mode)
    if mode != "ENHANCED":
        return unknown("unknown registry scanning mode")
    matched = []
    for rule in list_of_objects(get(configuration, "rules", list)):
        frequency = get(rule, "scanFrequency", str)
        if frequency not in {"SCAN_ON_PUSH", "CONTINUOUS_SCAN", "MANUAL"}:
            return unknown("unknown scanning frequency")
        for selected in list_of_objects(get(rule, "repositoryFilters", list)):
            kind, pattern = get(selected, "filterType", str), get(selected, "filter", str)
            if kind != "WILDCARD":
                return unknown("unknown repository filter type")
            if fnmatchcase(name, pattern) and frequency in {"SCAN_ON_PUSH", "CONTINUOUS_SCAN"}:
                matched.append({"filter": pattern, "scan_frequency": frequency})
    return result(not matched, repository=name, matching_scanning_rules=matched, semantics="Corrected repository-specific configuration; enhanced filters override legacy scanOnPush, and unmatched repositories are Off. No scan execution was requested.")
