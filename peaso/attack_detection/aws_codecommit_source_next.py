"""CodeCommit targeted data reads and Git protocol transfers.

Source bytes, file paths and commit/blob identifiers are not copied into
normalized detection evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_SOURCE = "codecommit.amazonaws.com"
_FLAGS = {
    "GetFile": "request.codecommit_known_file_read",
    "GetBlob": "request.codecommit_known_blob_read",
    "GetCommit": "request.codecommit_known_commit_read",
    "GitPull": "request.codecommit_git_pull_transferred",
    "GitPush": "request.codecommit_git_push_transferred",
}
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_OBJECT = re.compile(r"[0-9a-fA-F]{40}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != _SOURCE:
        return None
    name = record.get("eventName")
    if not isinstance(name, str) or name not in _FLAGS:
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = record.get("userIdentity")
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str) or not record["eventTime"]
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name != "GitPush")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request, extra = record.get("requestParameters"), record.get("additionalEventData")
    request = request if isinstance(request, Mapping) else {}
    extra = extra if isinstance(extra, Mapping) else {}
    repo = extra.get("repositoryName") if name in {"GitPull", "GitPush"} else request.get("repositoryName")
    if not isinstance(repo, str) or not _REPO.fullmatch(repo):
        return None
    if name == "GetFile":
        path = request.get("filePath")
        if not isinstance(path, str) or not path or len(path) > 1024:
            return None
    elif name == "GetBlob":
        value = request.get("blobId")
        if not isinstance(value, str) or not _OBJECT.fullmatch(value):
            return None
    elif name == "GetCommit":
        value = request.get("commitId")
        if not isinstance(value, str) or not _OBJECT.fullmatch(value):
            return None
    elif extra.get("dataTransferred") is not True:
        return None
    return {"cloud.provider": "aws", "event.source": _SOURCE,
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": identity["arn"], "target.id": repo,
            _FLAGS[name]: True}
