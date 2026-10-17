"""Hosted GCP collector identity and project ownership proof.

The private key is read by the collector worker from a dedicated secret. It is
never included in a connector record, API response, release artifact, or plan.
"""
from __future__ import annotations

import json
import re
import secrets

PLATFORM_PROJECT = "billing-static-info-no-delete"
PLATFORM_EMAIL = (
    "hacktricks-cspm-sa-acc-third-p@billing-static-info-no-delete.iam.gserviceaccount.com"
)
PROOF_VALUE = "approved"
PROOF_LABEL = re.compile(r"hacktricks-cspm-[0-9a-f]{20}\Z")


def enabled(settings) -> bool:
    return bool(getattr(settings, "gcp_platform_sa_secret_arn", ""))


def new_proof_label() -> str:
    return "hacktricks-cspm-" + secrets.token_hex(10)


def project_id(scope: str) -> str:
    if not isinstance(scope, str):
        raise ValueError("GCP project scope required")
    value = scope.removeprefix("projects/")
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", value):
        raise ValueError("Hosted platform GCP scopes must be project IDs")
    return value


def approved_project(project: dict, label: str) -> bool:
    if not isinstance(project, dict) or not PROOF_LABEL.fullmatch(label):
        return False
    ident = project.get("projectId")
    name = project.get("name")
    if (not isinstance(ident, str) or ident == PLATFORM_PROJECT
            or not isinstance(name, str) or not re.fullmatch(r"projects/[0-9]+", name)
            or project.get("state") != "ACTIVE"):
        return False
    labels = project.get("labels")
    return isinstance(labels, dict) and labels.get(label) == PROOF_VALUE


def load_service_account(secret_arn: str) -> dict:
    """Read and check the one platform key inside the collector process."""
    if not secret_arn:
        raise ValueError("Hosted GCP service account secret is not configured")
    import boto3

    response = boto3.client("secretsmanager").get_secret_value(SecretId=secret_arn)
    raw = response.get("SecretString")
    try:
        info = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("Hosted GCP service account secret is malformed") from exc
    if (not isinstance(info, dict) or info.get("type") != "service_account"
            or info.get("project_id") != PLATFORM_PROJECT
            or info.get("client_email") != PLATFORM_EMAIL
            or info.get("token_uri") != "https://oauth2.googleapis.com/token"
            or not isinstance(info.get("private_key"), str) or not info["private_key"]):
        raise ValueError("Hosted GCP service account identity does not match configuration")
    return info
