"""ECR enhanced scanning selection and exclusion mode semantics."""
import copy
from peaso.checks import CHECKS, aws_b_ecr


def evaluator(cid):
    return next(check.evaluate for check in CHECKS if check.id == cid)


def test_enhanced_repository_filters_override_legacy_scan_on_push():
    check = evaluator("aws.b.ecr.effective_scan_configuration")
    index = copy.deepcopy(aws_b_ecr._GOOD_REGISTRY)
    item = {"repositoryName": "development-app", "imageScanningConfiguration": {"scanOnPush": True}}
    assert check(item, index)[0] == "FAIL"
    item["repositoryName"] = "production-app"
    assert check(item, index)[0] == "PASS"
    index["collections"]["ecr_registry_scanning_configuration"][0]["status"] = "partial"
    assert check(item, index)[0] == "UNKNOWN"


def test_basic_scan_on_push_requires_known_registry_mode():
    check = evaluator("aws.b.ecr.effective_scan_configuration")
    item = {"repositoryName": "app", "imageScanningConfiguration": {"scanOnPush": True}}
    assert check(item, {})[0] == "UNKNOWN"
    index = {"collections": {"ecr_registry_scanning_configuration": [{"status": "collected"}]}, "ecr_registry_scanning_configuration": [{"data": {"scanningConfiguration": {"scanType": "BASIC"}}}]}
    assert check(item, index)[0] == "PASS"
    item["imageScanningConfiguration"]["scanOnPush"] = False
    assert check(item, index)[0] == "FAIL"


def test_new_exclusion_modes_are_not_full_repository_immutability():
    check = evaluator("aws.b.ecr.all_tags_immutable")
    assert check({"imageTagMutability": "IMMUTABLE"}, {})[0] == "PASS"
    for mode in ("MUTABLE", "MUTABLE_WITH_EXCLUSION", "IMMUTABLE_WITH_EXCLUSION"):
        assert check({"imageTagMutability": mode}, {})[0] == "FAIL"
    assert check({"imageTagMutability": "FUTURE_MODE"}, {})[0] == "UNKNOWN"
