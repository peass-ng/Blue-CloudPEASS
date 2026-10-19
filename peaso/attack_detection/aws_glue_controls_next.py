"""Small Glue CloudTrail facts for catalog, connection, job and trigger review."""

from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any


def normalize_aws_glue_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "glue.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"GetConnection", "UpdateTable", "UpdateJob", "CreateTrigger", "PutResourcePolicy"}:
        return None
    if record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall" or record.get("managementEvent") is not True:
        return None
    read = name == "GetConnection"
    if record.get("readOnly") is not read:
        return None
    request = record.get("requestParameters")
    account = record.get("recipientAccountId")
    if not isinstance(request, Mapping) or not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage") or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    table = request.get("tableInput")
    table = table if isinstance(table, Mapping) else {}
    storage = table.get("storageDescriptor")
    storage = storage if isinstance(storage, Mapping) else {}
    job = request.get("jobUpdate")
    job = job if isinstance(job, Mapping) else {}
    command = job.get("command")
    command = command if isinstance(command, Mapping) else {}
    actions = request.get("actions")
    scheduled_job = isinstance(actions, list) and any(isinstance(action, Mapping) and isinstance(action.get("jobName"), str) and bool(action["jobName"]) for action in actions)
    external_catalog_grant = False
    if name == "PutResourcePolicy":
        document = request.get("policyInJson")
        if isinstance(document, str):
            try:
                document = json.loads(document)
            except ValueError:
                document = None
        statements = document.get("Statement") if isinstance(document, Mapping) else None
        if isinstance(statements, Mapping):
            statements = [statements]
        if isinstance(statements, list):
            for statement in statements:
                if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
                    continue
                actions_in_policy = statement.get("Action")
                if isinstance(actions_in_policy, str):
                    actions_in_policy = [actions_in_policy]
                resources = statement.get("Resource")
                if isinstance(resources, str):
                    resources = [resources]
                if not isinstance(actions_in_policy, list) or not isinstance(resources, list):
                    continue
                if not any(isinstance(action, str) and action.lower() in {"glue:getdatabase", "glue:gettables", "glue:gettable", "glue:*", "*"} for action in actions_in_policy):
                    continue
                if not any(isinstance(resource, str) and resource.startswith("arn:aws:glue:")
                           and f":{account}:" in resource for resource in resources):
                    continue
                principal = statement.get("Principal")
                principals = principal.get("AWS") if isinstance(principal, Mapping) else principal
                if isinstance(principals, str):
                    principals = [principals]
                condition = statement.get("Condition")
                equal = condition.get("StringEquals") if isinstance(condition, Mapping) else None
                other_account = equal.get("aws:PrincipalAccount") if isinstance(equal, Mapping) else None
                external = isinstance(principals, list) and any(
                    isinstance(p, str) and p != "*" and (
                        p.isdigit() and len(p) == 12 and p != account
                        or p.startswith("arn:aws:iam::") and p.split(":")[4] != account
                    ) for p in principals)
                scoped_wildcard = principals == ["*"] and isinstance(other_account, str) and other_account.isdigit() and len(other_account) == 12 and other_account != account
                if external or scoped_wildcard:
                    external_catalog_grant = True
                    break
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    target = request.get("name") or request.get("jobName") or request.get("databaseName")
    return {
        "cloud.provider": "aws", "event.source": record.get("eventSource"),
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.glue_connection_password_visible_read": (
            name == "GetConnection" and isinstance(request.get("name"), str)
            and bool(request["name"]) and request.get("hidePassword") not in (True, "true") and not failed
        ),
        "request.glue_table_location_skip_archive": (
            name == "UpdateTable" and request.get("skipArchive") is True
            and isinstance(request.get("databaseName"), str) and bool(request["databaseName"])
            and isinstance(table.get("name"), str) and bool(table["name"])
            and isinstance(storage.get("location"), str) and storage["location"].startswith("s3://")
            and not failed
        ),
        "request.glue_job_script_set": (
            name == "UpdateJob" and isinstance(request.get("jobName"), str)
            and bool(request["jobName"]) and isinstance(command.get("scriptLocation"), str)
            and command["scriptLocation"].startswith("s3://") and not failed
        ),
        "request.glue_scheduled_job_trigger_activated": (
            name == "CreateTrigger" and request.get("type") == "SCHEDULED"
            and request.get("startOnCreation") is True and scheduled_job
            and isinstance(request.get("schedule"), str) and bool(request["schedule"])
            and not failed
        ),
        "request.glue_external_catalog_grant": name == "PutResourcePolicy" and external_catalog_grant and not failed,
    }
