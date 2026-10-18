"""Regional service-presence and settings assessments over complete fact sets."""
from . import result, unknown
from .facts import get, list_of_objects, complete_items
from .fixtures import CASES
from .aws_b_core import install, scalar, SOURCES


def _scope_present(kind, query, title):
    cid = "aws.b." + kind + ".regional_presence"
    anchor = {"scope": "111111111111/us-east-1"}
    common = {"collections": {kind: [{"scope": anchor["scope"], "status": "empty"}]}, kind: [], "context": anchor}
    positive = {"collections": {kind: [{"scope": anchor["scope"], "status": "collected"}]}, kind: [{"data": {"id": "configured"}}], "context": anchor}
    @install(cid, kind, title, anchor, anchor, query=query, target="scope", dependencies=[kind], extra={"pass_index": positive, "fail_index": common})
    def evaluate(item, index):
        scope = get(item, "scope", str)
        facts = complete_items(index, kind)
        return result(not facts, scope=scope, inventory=kind, observed_configurations=len(facts), semantics="Complete scoped inventory; known empty means required regional service configuration is absent.")


_scope_present("backup_plan", "backup_plan_region_configured", "A backup plan exists in each selected region")
_scope_present("backup_vault", "backup_vault_region_configured", "A backup vault exists in each selected region")


_report_anchor = {"scope": "111111111111/us-east-1"}
_report_base = {"collections": {"backup_plan": [{"status": "collected"}], "backup_report_plan": [{"status": "empty"}]}, "backup_plan": [{"data": {"id": "plan"}}], "backup_report_plan": []}
_report_good = {**_report_base, "collections": {"backup_plan": [{"status": "collected"}], "backup_report_plan": [{"status": "collected"}]}, "backup_report_plan": [{"data": {"id": "report"}}]}
@install("aws.b.backup.report_plan_presence", "backup_report_plan", "Regions with backup plans also have a backup report plan", _report_anchor, _report_anchor, query="backup_report_plan_configured", target="scope", dependencies=["backup_plan", "backup_report_plan"], empty_applicability_dependencies=["backup_plan"], extra={"pass_index": _report_good, "fail_index": _report_base})
def backup_report(item, index):
    scope = get(item, "scope", str)
    plans = complete_items(index, "backup_plan")
    if not plans:
        return "NOT_APPLICABLE", {"scope": scope, "backup_plans": 0, "reason": "Complete backup plan inventory is empty in this account and Region; the pinned source query returns info because no backup plan is configured."}
    reports = complete_items(index, "backup_report_plan")
    return result(not reports, scope=scope, backup_plans=len(plans), backup_report_plans=len(reports))


for _service, _field in (("ec2", "ec2"), ("ecr", "ecr"), ("lambda", "lambda"), ("lambda_code", "lambdaCode")):
    def _inspector(service, field):
        cid = "aws.b.inspector." + service + "_organization_auto_enable"
        anchor = {"scope": "111111111111/us-east-1"}
        def index(enabled):
            return {"collections": {"inspector_organization_configuration": [{"status": "collected"}]}, "inspector_organization_configuration": [{"data": {"autoEnable": {field: enabled}}}]}
        @install(cid, "inspector_organization_configuration", "Inspector organization automatically enables " + service + " scanning", anchor, anchor, query="inspector_" + service + "_scanning_enabled", target="scope", dependencies=["inspector_organization_configuration"], extra={"pass_index": index(True), "fail_index": index(False)})
        def evaluate(item, index):
            scope = get(item, "scope", str)
            facts = complete_items(index, "inspector_organization_configuration")
            envelopes = index.get("collections", {}).get("inspector_organization_configuration") or []
            states = {(e.get("error") or {}).get("code") for e in envelopes if isinstance(e, dict) and e.get("status") == "empty"}
            if not facts and "not_delegated_administrator" in states:
                # DescribeOrganizationConfiguration documented reply for an account that is not the Inspector delegated administrator.
                return "NOT_APPLICABLE", {"scope": scope, "service": service, "reason": "Caller is not the Inspector delegated administrator; organization auto-enable is not readable or configurable here."}
            if not facts and "region_operation_unsupported" in states:
                # Exact UnknownOperationException reply: the Region does not offer the operation, so nothing is configurable.
                return "NOT_APPLICABLE", {"scope": scope, "service": service, "reason": "Inspector organization configuration is not offered in this Region."}
            if not facts:
                return result(True, scope=scope, service=service, reason="Complete empty organization configuration inventory.")
            if len(facts) != 1:
                return unknown("organization configuration did not resolve uniquely")
            enabled = get(facts[0], "autoEnable." + field, bool)
            return result(not enabled, scope=scope, auto_enable_service=service, auto_enable=enabled, semantics="Organization auto-enable configuration, not a claim that existing account resources were scanned.")
    _inspector(_service, _field)


scalar("aws.b.ssm.parameter_secure_type", "ssm_parameter_metadata", "Type", "SecureString", "String", "SSM Parameter Store metadata has SecureString type", "ssm_parameter_encryption_enabled", allowed={"SecureString", "String", "StringList"})


@install("aws.b.ssm.document_not_public", "ssm_document_metadata", "SSM document sharing metadata excludes the all-account principal", {"Owner": "111111111111", "Permissions": {"AccountIds": ["111111111111"]}}, {"Owner": "111111111111", "Permissions": {"AccountIds": ["all"]}}, query="ssm_document_prohibit_public_access", category="exposure", extra={"index": {"context": {"Account": "111111111111"}}, "not_applicable": {"Owner": "Amazon"}})
def document_sharing(item, index):
    owner = get(item, "Owner", str)
    if owner in ("Amazon", "AWS"):
        return "NOT_APPLICABLE", {"owner": owner, "reason": "Source filters owner_type Self."}
    caller = index.get("context", {}).get("Account")
    if not caller:
        return unknown("caller account identity needed for document owner join")
    if owner != caller:
        return "NOT_APPLICABLE", {"owner": owner, "reason": "Document is owned by another account, excluded by source Self scope."}
    accounts = get(item, "Permissions.AccountIds", list)
    if any(not isinstance(v, str) for v in accounts):
        return unknown("malformed document sharing accounts")
    return result("all" in accounts, shared_accounts=accounts, semantics="Sharing metadata only; document content and server execution are not requested.")


@install("aws.b.dynamodb.kms_description", "dynamodb_table", "DynamoDB table has an SSEDescription object", {"Table": {"Table": {"TableName": "table", "SSEDescription": {"SSEType": "KMS"}}}}, {"Table": {"Table": {"TableName": "table"}}}, query="dynamodb_table_encrypted_with_kms")
def dynamo_kms(item, index):
    table = get(item, "Table.Table", dict)
    get(table, "TableName", str)
    description = table.get("SSEDescription")
    if description is not None and not isinstance(description, dict):
        return unknown("malformed SSE description")
    return result(description is None, sse_description=description, semantics="Exact source description-presence control; DynamoDB-owned default encryption remains a separate passing security baseline.")


@install("aws.b.dynamodb.encryption_type", "dynamodb_table", "DynamoDB table uses KMS or the documented default SSE configuration", {"Table": {"Table": {"TableName": "table"}}}, {"Table": {"Table": {"TableName": "table", "SSEDescription": {"SSEType": "AES256"}}}}, query="dynamodb_table_encryption_enabled")
def dynamo_default(item, index):
    table = get(item, "Table.Table", dict)
    get(table, "TableName", str)
    description = table.get("SSEDescription")
    if description is None:
        return result(False, encryption="DynamoDB-owned default SSE", semantics="Successful native table metadata and AWS-documented mandatory encryption default.")
    kind = get(description, "SSEType", str)
    if kind not in {"KMS", "AES256"}:
        return unknown("unknown SSE type")
    return result(kind != "KMS", sse_type=kind)


scalar("aws.b.dynamodb.deletion_protection", "dynamodb_table", "Table.Table.DeletionProtectionEnabled", True, False, "DynamoDB table deletion protection is enabled", "dynamodb_table_deletion_protection_enabled")
