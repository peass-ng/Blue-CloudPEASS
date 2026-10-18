"""Normalize an observed IAM console credential created for another user."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_USER = re.compile(r"[\w+=,.@-]{1,64}\Z", re.ASCII)


def _time(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _actor(identity: Mapping[str, Any], account: str) -> tuple[str, str, str | None] | None:
    if identity.get("accountId") != account:
        return None
    actor_name, actor_arn = identity.get("userName"), identity.get("arn")
    actor_parts = actor_arn.split(":", 5) if isinstance(actor_arn, str) else []
    if len(actor_parts) != 6 or actor_parts[0] != "arn" or actor_parts[1] not in {"aws", "aws-us-gov", "aws-cn"}:
        return None
    actor_kind = identity.get("type")
    if actor_kind == "IAMUser":
        if (not isinstance(actor_name, str) or _USER.fullmatch(actor_name) is None
                or actor_parts[2:5] != ["iam", "", account]
                or not actor_parts[5].startswith("user/")
                or actor_parts[5].split("/")[-1] != actor_name
                or any(not segment for segment in actor_parts[5].split("/")[1:])):
            return None
    elif actor_kind == "AssumedRole":
        session = identity.get("sessionContext")
        issuer = session.get("sessionIssuer") if isinstance(session, Mapping) else None
        issuer_arn = issuer.get("arn") if isinstance(issuer, Mapping) else None
        issuer_parts = issuer_arn.split(":", 5) if isinstance(issuer_arn, str) else []
        assumed = actor_parts[5].split("/")
        if (actor_parts[2:5] != ["sts", "", account]
                or len(assumed) != 3 or assumed[0] != "assumed-role"
                or not assumed[1] or not assumed[2]
                or not isinstance(issuer, Mapping) or issuer.get("type") != "Role"
                or issuer.get("accountId", account) != account
                or len(issuer_parts) != 6 or issuer_parts[:5] != ["arn", actor_parts[1], "iam", "", account]
                or not issuer_parts[5].startswith("role/")
                or issuer_parts[5].split("/")[-1] != assumed[1]):
            return None
    else:
        return None
    return actor_arn, actor_kind, actor_name if isinstance(actor_name, str) else None


def normalize_aws_other_user_login_profile(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Require a successful CreateLoginProfile and a matching returned profile.

    The password never enters canonical evidence. This event does not prove
    later sign-in, the target's permissions, or malicious intent.
    """
    if not isinstance(record, Mapping) or (record.get("eventSource"), record.get("eventName")) != (
        "iam.amazonaws.com", "CreateLoginProfile"
    ):
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account = record.get("recipientAccountId")
    event_id, event_time = record.get("eventID"), record.get("eventTime")
    if (not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None
            or not isinstance(event_id, str) or not event_id or not _time(event_time)):
        return None
    identity, request, response = (
        record.get("userIdentity"), record.get("requestParameters"), record.get("responseElements")
    )
    if not all(isinstance(item, Mapping) for item in (identity, request, response)):
        return None
    assert isinstance(identity, Mapping) and isinstance(request, Mapping) and isinstance(response, Mapping)
    actor = _actor(identity, account)
    if actor is None:
        return None
    actor_arn, actor_kind, actor_name = actor
    target_name = request.get("userName")
    if (not isinstance(target_name, str) or _USER.fullmatch(target_name) is None
            or (actor_kind == "IAMUser" and target_name == actor_name)
            or request.get("passwordResetRequired") is not False):
        return None
    profile = response.get("loginProfile")
    if (not isinstance(profile, Mapping) or profile.get("userName") != target_name
            or profile.get("passwordResetRequired") is not False
            or not _time(profile.get("createDate"))):
        return None
    if response.get("errorCode") or response.get("errorMessage"):
        return None
    return {
        "cloud.provider": "aws", "event.source": "iam.amazonaws.com",
        "event.name": "CreateLoginProfile", "event.outcome": "success",
        "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn,
        "actor.kind": actor_kind,
        "target.id": f"iam-user:{account}:{target_name}",
        "request.other_user": True, "request.password_reset_required": False,
        "response.login_profile_matches_target": True,
    }


def normalize_aws_other_user_login_profile_update(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Observe another user's login profile updated with reset disabled.

    CloudTrail omits the password field, so the event cannot distinguish a
    password replacement from an update of PasswordResetRequired alone.
    """
    if not isinstance(record, Mapping) or (record.get("eventSource"), record.get("eventName")) != (
        "iam.amazonaws.com", "UpdateLoginProfile"
    ):
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage") or "responseElements" not in record):
        return None
    response = record.get("responseElements")
    if response is not None and (not isinstance(response, Mapping)
                                 or response.get("errorCode") or response.get("errorMessage")):
        return None
    account = record.get("recipientAccountId")
    event_id, event_time = record.get("eventID"), record.get("eventTime")
    if (not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None
            or not isinstance(event_id, str) or not event_id or not _time(event_time)):
        return None
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if not isinstance(identity, Mapping) or not isinstance(request, Mapping):
        return None
    actor = _actor(identity, account)
    if actor is None:
        return None
    actor_arn, actor_kind, actor_name = actor
    target_name = request.get("userName")
    if (not isinstance(target_name, str) or _USER.fullmatch(target_name) is None
            or (actor_kind == "IAMUser" and target_name == actor_name)
            or request.get("passwordResetRequired") is not False):
        return None
    return {
        "cloud.provider": "aws", "event.source": "iam.amazonaws.com",
        "event.name": "UpdateLoginProfile", "event.outcome": "success",
        "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": actor_kind,
        "target.id": f"iam-user:{account}:{target_name}",
        "request.other_user": True, "request.password_reset_required": False,
        "request.profile_update_observed": True,
    }
