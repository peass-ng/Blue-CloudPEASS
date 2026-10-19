"""Accepted AppConfig content-bearing extension and application association events."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_CONTENT_POINTS = {"PRE_CREATE_HOSTED_CONFIGURATION_VERSION", "PRE_START_DEPLOYMENT"}


def normalize_aws_appconfig_extension(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "appconfig.amazonaws.com"
            or name not in {"CreateExtension", "CreateExtensionAssociation",
                            "CreateConfigurationProfile", "StartDeployment",
                            "CreateExperimentDefinition", "StartExperimentRun"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or (not isinstance(response, Mapping)
                                             and name != "CreateExperimentDefinition"):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(region, str):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    content_hook = False
    app_association = False
    secret_profile = False
    secret_deployment = False
    experiment_enabled = False
    experiment_running = False
    target = response.get("arn") if isinstance(response, Mapping) else None
    if name == "CreateExtension":
        actions = request.get("actions")
        returned = response.get("actions")
        extension_id = response.get("id")
        expected = f"arn:aws:appconfig:{region}:{account}:extension/{extension_id}/1"
        if (isinstance(actions, Mapping) and actions == returned
                and isinstance(extension_id, str) and response.get("arn") == expected):
            for point in _CONTENT_POINTS:
                entries = actions.get(point)
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if not isinstance(entry, Mapping):
                        continue
                    uri, role = entry.get("uri"), entry.get("roleArn")
                    if (isinstance(uri, str) and re.fullmatch(
                            rf"arn:aws:lambda:{re.escape(region)}:{account}:function:[A-Za-z0-9-_]+(?::[A-Za-z0-9-_]+)?", uri)
                            and isinstance(role, str) and re.fullmatch(
                                rf"arn:aws:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+", role)):
                        content_hook = True
    elif name == "CreateExtensionAssociation":
        extension_id = request.get("extensionIdentifier")
        resource = request.get("resourceIdentifier")
        version = response.get("extensionVersionNumber")
        association_id = response.get("id")
        app_association = (
            isinstance(extension_id, str) and isinstance(version, int)
            and response.get("extensionArn") == f"arn:aws:appconfig:{region}:{account}:extension/{extension_id}/{version}"
            and isinstance(resource, str) and re.fullmatch(
                rf"arn:aws:appconfig:{re.escape(region)}:{account}:application/[A-Za-z0-9]+", resource) is not None
            and response.get("resourceArn") == resource
            and isinstance(association_id, str)
            and response.get("arn") == f"arn:aws:appconfig:{region}:{account}:extensionassociation/{association_id}"
        )
    elif name == "CreateConfigurationProfile":
        application_id, profile_id = request.get("applicationId"), response.get("id")
        location, role = request.get("locationUri"), request.get("retrievalRoleArn")
        secret_profile = (
            isinstance(application_id, str) and re.fullmatch(r"[a-z0-9]{4,7}", application_id) is not None
            and isinstance(profile_id, str) and re.fullmatch(r"[a-z0-9]{4,7}", profile_id) is not None
            and response.get("applicationId") == application_id
            and isinstance(location, str) and re.fullmatch(r"secretsmanager://[A-Za-z0-9/_+=.@:-]+", location) is not None
            and response.get("locationUri") == location
            and isinstance(role, str) and re.fullmatch(rf"arn:aws:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+", role) is not None
            and response.get("retrievalRoleArn") == role
        )
        target = f"arn:aws:appconfig:{region}:{account}:application/{application_id}/configurationprofile/{profile_id}" if secret_profile else None
    elif name == "StartDeployment":
        application_id = request.get("applicationId")
        profile_id = request.get("configurationProfileId")
        environment_id = request.get("environmentId")
        location = response.get("configurationLocationUri")
        secret_deployment = (
            all(isinstance(x, str) and re.fullmatch(r"[a-z0-9]{4,7}", x)
                for x in (application_id, profile_id, environment_id))
            and response.get("applicationId") == application_id
            and response.get("configurationProfileId") == profile_id
            and response.get("environmentId") == environment_id
            and response.get("configurationVersion") == request.get("configurationVersion")
            and isinstance(location, str) and re.fullmatch(r"secretsmanager://[A-Za-z0-9/_+=.@:-]+", location) is not None
            and isinstance(response.get("deploymentNumber"), int)
        )
        target = f"arn:aws:appconfig:{region}:{account}:application/{application_id}/environment/{environment_id}/deployment/{response.get('deploymentNumber')}" if secret_deployment else None
    elif name == "CreateExperimentDefinition":
        application_id = request.get("applicationIdentifier")
        profile_id = request.get("configurationProfileIdentifier")
        environment_id = request.get("environmentIdentifier")
        treatments = request.get("treatments")
        control = request.get("control")
        experiment_enabled = (
            all(isinstance(x, str) and re.fullmatch(r"[a-z0-9]{4,7}", x)
                for x in (application_id, profile_id, environment_id))
            and isinstance(control, Mapping)
            and isinstance(control.get("flagValue"), Mapping)
            and control["flagValue"].get("enabled") is False
            and isinstance(treatments, list)
            and any(isinstance(t, Mapping) and isinstance(t.get("flagValue"), Mapping)
                    and t["flagValue"].get("enabled") is True
                    and isinstance(t.get("weight"), (int, float)) and t["weight"] > 0
                    for t in treatments)
        )
        target = f"arn:aws:appconfig:{region}:{account}:application/{application_id}" if experiment_enabled else None
    else:
        application_id = request.get("applicationIdentifier")
        definition_id = request.get("experimentDefinitionIdentifier")
        snapshot = response.get("experimentDefinitionSnapshot")
        treatments = snapshot.get("treatments") if isinstance(snapshot, Mapping) else None
        control = snapshot.get("control") if isinstance(snapshot, Mapping) else None
        exposure = response.get("exposurePercentage")
        experiment_running = (
            isinstance(application_id, str) and re.fullmatch(r"[a-z0-9]{4,7}", application_id) is not None
            and isinstance(definition_id, str) and re.fullmatch(r"[a-z0-9]{4,7}", definition_id) is not None
            and response.get("applicationId") == application_id
            and response.get("experimentDefinitionId") == definition_id
            and response.get("status") == "RUNNING"
            and isinstance(exposure, (int, float)) and exposure > 0
            and exposure == request.get("exposurePercentage")
            and isinstance(control, Mapping) and isinstance(control.get("flagValue"), Mapping)
            and control["flagValue"].get("enabled") is False
            and isinstance(treatments, list)
            and any(isinstance(t, Mapping) and isinstance(t.get("flagValue"), Mapping)
                    and t["flagValue"].get("enabled") is True
                    and isinstance(t.get("weight"), (int, float)) and t["weight"] > 0
                    for t in treatments)
        )
        target = f"arn:aws:appconfig:{region}:{account}:application/{application_id}/experimentdefinition/{definition_id}" if experiment_running else None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "appconfig.amazonaws.com",
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
            "request.appconfig_content_hook_created": not failed and content_hook,
            "request.appconfig_app_wide_extension_association": not failed and app_association,
            "request.appconfig_secret_retrieval_profile": not failed and secret_profile,
            "request.appconfig_secret_source_deployment": not failed and secret_deployment,
            "request.appconfig_enabled_experiment_defined": not failed and experiment_enabled,
            "request.appconfig_enabled_experiment_running": not failed and experiment_running}
