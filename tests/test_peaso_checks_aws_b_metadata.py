"""Metadata plugin uses shared read-only calls and never retains configuration secrets."""
from types import SimpleNamespace
from botocore.session import get_session
from peaso.collectors import aws_b_services as plugin


def test_read_operations_exist_and_configuration_only():
    sdk = get_session()
    for service, operation in plugin.READ_ACTIONS:
        names = {name.lower() for name in sdk.get_service_model(service).operation_names}
        assert operation.replace("_", "").lower() in names
        assert operation.startswith(("list_", "describe_", "get_", "batch_get_"))
        assert operation not in {"get_secret_value", "get_parameter", "get_parameters", "get_document", "get_function", "get_object"}


def test_metadata_redaction_preserves_security_configuration():
    data = {"environment": {"privilegedMode": True, "environmentVariables": [{"name": "CREDENTIAL", "value": "PRIVATE_SENTINEL"}]},
            "containerDefinitions": [{"name": "app", "privileged": False, "environment": [{"name": "TOKEN", "value": "PRIVATE_SENTINEL"}], "command": ["PRIVATE_SENTINEL"]}],
            "ClientSecret": "PRIVATE_SENTINEL", "Config": {"Encryption": True}}
    safe = plugin._metadata(data)
    assert "PRIVATE_SENTINEL" not in str(safe)
    assert safe["environment"]["privilegedMode"] is True
    assert safe["containerDefinitions"][0]["privileged"] is False
    assert safe["Config"]["Encryption"] is True


class Reads:
    def __init__(self):
        self.calls = []
    def detail(self, session, service, region, operation, **arguments):
        self.calls.append((service, operation, arguments))
        if operation == "get_function_configuration":
            return {"FunctionName": "f", "TracingConfig": {"Mode": "Active"}, "Environment": {"Variables": {"TOKEN": "PRIVATE_SENTINEL"}}}
        if operation == "get_function_concurrency":
            return {"ReservedConcurrentExecutions": 0}
        if operation == "describe_continuous_backups":
            return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}}}
        return {"collection_status": "denied", "error": {"code": "AccessDenied"}}
    def pages(self, session, service, region, operation, expression, **arguments):
        self.calls.append((service, operation, arguments))
        return SimpleNamespace(items=[], status="empty", error=None)


def test_lambda_and_dynamo_enrichment_stays_native_and_denied_details_explicit():
    reads = Reads()
    result = plugin.ENRICHERS["lambda_function"](reads, object(), "us-east-1", [{"FunctionName": "f"}])
    assert result[0]["Concurrency"]["ReservedConcurrentExecutions"] == 0
    assert result[0]["Configuration"]["TracingConfig"]["Mode"] == "Active"
    assert "PRIVATE_SENTINEL" not in str(result)
    result = plugin.ENRICHERS["dynamodb_table"](reads, object(), "us-east-1", [{"TableName": "table"}])
    assert result[0]["ContinuousBackups"]["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "ENABLED"
    result = plugin.ENRICHERS["acm_certificate"](reads, object(), "us-east-1", [{"CertificateArn": "arn:cert"}])
    assert result[0]["Certificate"]["collection_status"] == "denied"


def test_cognito_list_required_page_size_is_supplied():
    reads = Reads()
    result = plugin.FETCHERS["cognito_user_pool"](reads, object(), "us-east-1", "111111111111")
    assert result.status == "empty"
    assert reads.calls[0][2]["MaxResults"] == 60


def test_ecr_mutability_modes_and_filters_remain_native_without_boolean_collapse():
    reads = Reads()
    modes = ["MUTABLE", "IMMUTABLE", "MUTABLE_WITH_EXCLUSION", "IMMUTABLE_WITH_EXCLUSION"]
    items = [{"repositoryName": "repo-" + str(i), "imageTagMutability": mode, **({"imageTagMutabilityExclusionFilters": [{"filterType": "WILDCARD", "filter": "stable-*"}]} if "EXCLUSION" in mode else {})} for i, mode in enumerate(modes)]
    result = plugin.ENRICHERS["ecr_repository"](reads, object(), "us-east-1", items)
    assert reads.calls == []
    assert [item["imageTagMutability"] for item in result] == modes
    assert result[2]["imageTagMutabilityExclusionFilters"] == items[2]["imageTagMutabilityExclusionFilters"]
    assert all(item["_coverage"]["imageTagMutability"]["status"] == "collected" for item in result)


def test_missing_ecr_mutability_detail_is_denied_not_an_invented_mode():
    reads = Reads()
    result = plugin.ENRICHERS["ecr_repository"](reads, object(), "us-east-1", [{"repositoryName": "repo"}])
    assert "imageTagMutability" not in result[0]
    assert result[0]["_coverage"]["imageTagMutability"]["status"] == "denied"
    assert reads.calls == [("ecr", "describe_repositories", {"repositoryNames": ["repo"]})]


def test_ecr_missing_field_successful_collected_detail_hydrates_raw_mode():
    class Success(Reads):
        def detail(self, session, service, region, operation, **arguments):
            self.calls.append((service, operation, arguments))
            return {"collection_status": "collected", "repositories": [{"repositoryName": "repo", "imageTagMutability": "IMMUTABLE_WITH_EXCLUSION", "imageTagMutabilityExclusionFilters": [{"filterType": "WILDCARD", "filter": "development-*"}]}]}
    reads = Success()
    result = plugin.ENRICHERS["ecr_repository"](reads, object(), "us-east-1", [{"repositoryName": "repo"}])
    assert result[0]["imageTagMutability"] == "IMMUTABLE_WITH_EXCLUSION"
    assert result[0]["_coverage"]["imageTagMutability"]["status"] == "collected"
    assert len(reads.calls) == 1
