"""Defensive admin-only Inspector review, separate from literal source controls."""
import re
from . import result, unknown
from .facts import get, complete_items
from .aws_b_core import install, IDS as ALL_IDS

_before = set(ALL_IDS)
KIND = "inspector_organization_review"
DOCS = ["https://docs.aws.amazon.com/inspector/v2/APIReference/API_GetDelegatedAdminAccount.html",
        "https://docs.aws.amazon.com/inspector/latest/user/admin-member-relationship.html"]


def _index(service, enabled):
    return {"context": {"Account": "111111111111"}, "collections": {KIND: [{"status": "collected"}]},
            KIND: [{"data": {"AccountId": "111111111111",
                "Administrator": {"collection_status": "collected", "delegatedAdmin": {"accountId": "111111111111", "relationshipStatus": "ENABLED"}},
                "Configuration": {"collection_status": "collected", "autoEnable": {service: enabled}}}}]}


for _service, _field in (("ec2", "ec2"), ("ecr", "ecr"), ("lambda", "lambda"), ("lambda_code", "lambdaCode")):
    def _define(service, field):
        anchor = {"scope": "111111111111/us-east-1"}
        @install("aws.b.inspector.admin_" + service + "_auto_enable", KIND,
                 "Verified Inspector delegated administrator automatically enables " + service + " scanning",
                 anchor, anchor, target="scope", dependencies=[KIND],
                 extra={"pass_index": _index(field, True), "fail_index": _index(field, False)})
        def evaluate(item, index):
            caller = index.get("context", {}).get("Account")
            if not isinstance(caller, str) or not re.fullmatch(r"\d{12}", caller):
                return unknown("verified caller account context unavailable")
            facts = complete_items(index, KIND)
            if len(facts) != 1 or get(facts[0], "AccountId", str) != caller:
                return unknown("Inspector review caller binding missing or ambiguous")
            record = facts[0]
            administrator = record.get("Administrator")
            if not isinstance(administrator, dict):
                return unknown("delegated administrator proof not collected")
            admin_status = administrator.get("collection_status")
            if admin_status == "denied":
                return "DENIED", {"reason": "delegated administrator proof denied", "read_status": admin_status}
            if admin_status == "empty" and administrator.get("absent") is True and (administrator.get("error") or {}).get("code") == "no_delegated_administrator":
                # GetDelegatedAdminAccount documented "No delegated admin found for caller account": no administrator exists to verify.
                return "NOT_APPLICABLE", {"reason": "No Inspector delegated administrator is configured for the caller account.",
                    "caller_account": caller, "read_status": admin_status, "official_references": DOCS}
            if admin_status != "collected":
                return unknown("delegated administrator proof unavailable", read_status=admin_status)
            admin = get(administrator, "delegatedAdmin", dict)
            account = get(admin, "accountId", str)
            relationship = get(admin, "relationshipStatus", str)
            if not re.fullmatch(r"\d{12}", account) or relationship != "ENABLED":
                return unknown("no positively enabled delegated administrator proof", relationship_status=relationship)
            if account != caller:
                config = record.get("Configuration")
                return "NOT_APPLICABLE", {"reason": "Native enabled delegated-administrator proof identifies a different account.",
                    "caller_account": caller, "delegated_admin_account": account, "relationship_status": relationship,
                    "configuration_read_status": config.get("collection_status") if isinstance(config, dict) else "malformed", "official_references": DOCS}
            configuration = record.get("Configuration")
            if isinstance(configuration, dict) and configuration.get("collection_status") == "denied":
                return "DENIED", {"reason": "organization configuration denied for verified administrator", "caller_account": caller}
            enabled = get(record, "Configuration.autoEnable." + field, bool)
            return result(not enabled, caller_account=caller, delegated_admin_account=account,
                          relationship_status=relationship, auto_enable_service=field, auto_enable=enabled,
                          official_references=DOCS,
                          semantics="Admin-only defensive variant; literal upstream regional LEFT JOIN predicates remain separate. Existing resource scanning is not asserted.")
    _define(_service, _field)

IDS = [cid for cid in ALL_IDS if cid not in _before]
