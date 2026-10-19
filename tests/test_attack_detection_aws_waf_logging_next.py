"""WAF logging must accept and return a DROP filter for the same ACL."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="waf-drop", title="WAF drops logs", level="medium", description="logs",
    technique_id="aws-waf-logging-filter-drops-requests", product="aws",
    selection={"event.source": "wafv2.amazonaws.com", "event.name": "PutLoggingConfiguration",
               "event.outcome": "success", "request.waf_logging_drops_traffic": True})
DELETE_RULES = [
    Rule(id="waf-logs-deleted", title="WAF logs deleted", level="medium", description="delete",
         technique_id="aws-waf-logging-configuration-deleted", product="aws",
         selection={"event.source": "wafv2.amazonaws.com",
                    "event.name": "DeleteLoggingConfiguration", "event.outcome": "success",
                    "request.waf_logging_deleted": True}),
    Rule(id="waf-acl-deleted", title="WAF ACL deleted", level="medium", description="delete",
         technique_id="aws-waf-web-acl-deleted", product="aws",
         selection={"event.source": "wafv2.amazonaws.com",
                    "event.name": "DeleteWebACL", "event.outcome": "success",
                    "request.waf_web_acl_deleted": True}),
]
REDACTION_RULE = Rule(id="waf-location-redacted", title="WAF location hidden", level="medium",
    description="redaction", technique_id="aws-waf-logging-location-redacted", product="aws",
    selection={"event.source": "wafv2.amazonaws.com", "event.name": "PutLoggingConfiguration",
               "event.outcome": "success", "request.waf_logging_redacts_location": True})
DISASSOC_RULE = Rule(id="waf-api-detached", title="API WAF detached", level="high",
    description="detach", technique_id="aws-waf-api-stage-disassociated", product="aws",
    selection={"event.source": "wafv2.amazonaws.com", "event.name": "DisassociateWebACL",
               "event.outcome": "success", "request.waf_api_stage_disassociated": True})
ARN = "arn:aws:wafv2:us-east-1:947247140022:regional/webacl/test-acl/a4fceb6d-1195-4087-9b83-4709e869a14c"


def _hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event], [RULE])]


def test_default_drop_and_rejected_variants() -> None:
    config = {"resourceArn": ARN, "logDestinationConfigs": ["arn:aws:s3:::aws-waf-logs-test"],
              "loggingFilter": {"defaultBehavior": "DROP", "filters": [{"behavior": "KEEP"}]}}
    event = {"eventSource": "wafv2.amazonaws.com", "eventName": "PutLoggingConfiguration",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "947247140022",
             "requestParameters": {"loggingConfiguration": deepcopy(config)},
             "responseElements": {"loggingConfiguration": deepcopy(config)}}
    assert _hits(event) == [RULE.technique_id]
    for variant in ("keep", "failed", "different_acl", "response_keeps", "data_event"):
        item = deepcopy(event)
        if variant == "keep":
            item["requestParameters"]["loggingConfiguration"]["loggingFilter"]["defaultBehavior"] = "KEEP"
            item["responseElements"]["loggingConfiguration"]["loggingFilter"]["defaultBehavior"] = "KEEP"
        if variant == "failed": item["errorCode"] = "WAFInvalidParameterException"
        if variant == "different_acl":
            item["responseElements"]["loggingConfiguration"]["resourceArn"] = ARN[:-1] + "0"
        if variant == "response_keeps":
            item["responseElements"]["loggingConfiguration"]["loggingFilter"]["defaultBehavior"] = "KEEP"
        if variant == "data_event": item["eventCategory"] = "Data"
        assert _hits(item) == [], variant


def test_uri_path_redacted_and_header_only_negative() -> None:
    config = {"resourceArn": ARN, "logDestinationConfigs": ["arn:aws:s3:::aws-waf-logs-test"],
              "redactedFields": [{"uriPath": {}}]}
    event = {"eventSource": "wafv2.amazonaws.com", "eventName": "PutLoggingConfiguration",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "947247140022",
             "requestParameters": {"loggingConfiguration": deepcopy(config)},
             "responseElements": {"loggingConfiguration": deepcopy(config)}}
    assert [x.technique_id for x in detect_aws_events([event], [REDACTION_RULE])] == [REDACTION_RULE.technique_id]
    for variant in ("header_only", "failed", "response_missing", "different_acl"):
        item = deepcopy(event)
        if variant == "header_only":
            item["requestParameters"]["loggingConfiguration"]["redactedFields"] = [{"singleHeader": {"name": "authorization"}}]
            item["responseElements"]["loggingConfiguration"]["redactedFields"] = [{"singleHeader": {"name": "authorization"}}]
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "response_missing":
            item["responseElements"]["loggingConfiguration"].pop("redactedFields")
        if variant == "different_acl":
            item["responseElements"]["loggingConfiguration"]["resourceArn"] = ARN[:-1] + "0"
        assert detect_aws_events([item], [REDACTION_RULE]) == [], variant


def test_waf_deletion_events_require_valid_target_and_success() -> None:
    base = {"eventSource": "wafv2.amazonaws.com", "eventCategory": "Management",
            "eventType": "AwsApiCall", "managementEvent": True, "readOnly": False,
            "recipientAccountId": "947247140022", "responseElements": None}
    for name, request, technique in (
        ("DeleteLoggingConfiguration", {"resourceArn": ARN},
         "aws-waf-logging-configuration-deleted"),
        ("DeleteWebACL", {"name": "test-acl", "scope": "REGIONAL",
                          "id": "a4fceb6d-1195-4087-9b83-4709e869a14c"},
         "aws-waf-web-acl-deleted"),
    ):
        event = {**base, "eventName": name, "requestParameters": request}
        assert [x.technique_id for x in detect_aws_events([event], DELETE_RULES)] == [technique]
        denied = deepcopy(event)
        denied["errorCode"] = "AccessDeniedException"
        assert detect_aws_events([denied], DELETE_RULES) == []
        missing = deepcopy(event)
        missing["requestParameters"] = {}
        assert detect_aws_events([missing], DELETE_RULES) == []


def test_waf_api_gateway_stage_disassociation() -> None:
    event = {"eventSource": "wafv2.amazonaws.com", "eventName": "DisassociateWebACL",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "947247140022",
             "requestParameters": {"resourceArn": "arn:aws:apigateway:us-east-1::/restapis/t8ltthq1h4/stages/test"},
             "responseElements": None}
    assert [x.technique_id for x in detect_aws_events([event], [DISASSOC_RULE])] == [DISASSOC_RULE.technique_id]
    for variant in ("failed", "bad_arn", "data_event"):
        item = deepcopy(event)
        if variant == "failed": item["errorCode"] = "WAFNonexistentItemException"
        if variant == "bad_arn": item["requestParameters"]["resourceArn"] = "not-an-api-stage"
        if variant == "data_event": item["eventCategory"] = "Data"
        assert detect_aws_events([item], [DISASSOC_RULE]) == [], variant
