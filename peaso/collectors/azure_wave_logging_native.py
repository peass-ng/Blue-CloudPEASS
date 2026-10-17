"""Validate bounded SecurityIncident history already obtained from Azure Logs.

This is a pure projector. It does not execute a query or equate status changes
with analyst triage, a response procedure, or incident-history completeness.
"""
from datetime import datetime, timedelta, timezone
import re


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
_STATUS = frozenset({"New", "Active", "Closed"})
_TASK = frozenset({"New", "Completed", "Deleted"})


def _time(value):
    if not isinstance(value, str):
        raise ValueError("history timestamp missing")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("history timestamp malformed") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("history timestamp lacks timezone")
    return stamp.astimezone(timezone.utc)


def project(incident_name, snapshots, proof):
    """Return observed status/task transitions with an explicit coverage bound.

    ``proof`` is a verified Logs query envelope, never an operator setting.
    The caller must attest the query's workspace/incident filters, complete
    pagination, retention start, and capture end from native read responses.
    """
    if not isinstance(incident_name, str) or not _NAME.fullmatch(incident_name):
        raise ValueError("incident name invalid")
    if not isinstance(proof, dict) or proof.get("source_operation") != "logs.query.SecurityIncident":
        raise ValueError("native SecurityIncident query proof unavailable")
    if proof.get("read_only") is not True or proof.get("complete") is not True:
        raise ValueError("SecurityIncident query incomplete")
    workspace = proof.get("workspace_id")
    if not isinstance(workspace, str) or not _GUID.fullmatch(workspace):
        raise ValueError("workspace query identity invalid")
    beginning = _time(proof.get("window_start"))
    ending = _time(proof.get("window_end"))
    if proof.get("retention_source_operation") != "operationalinsights.tables.get":
        raise ValueError("native table retention proof unavailable")
    days = proof.get("analytics_retention_days")
    if type(days) is not int or not 4 <= days <= 730:
        raise ValueError("analytics retention period invalid")
    observed = _time(proof.get("retention_observed_at"))
    retention = observed - timedelta(days=days)
    if ending > observed:
        raise ValueError("query ends after retention observation")
    if not retention <= beginning < ending:
        raise ValueError("query window exceeds observed retention")
    if not isinstance(snapshots, list) or len(snapshots) > 10000 or not snapshots:
        raise ValueError("bounded nonempty SecurityIncident snapshots required")
    previous_at = None
    previous_status = None
    task_states = {}
    statuses, tasks = [], []
    created_at = None
    for row in snapshots:
        if not isinstance(row, dict) or row.get("Type") != "SecurityIncident" or row.get("IncidentName") != incident_name:
            raise ValueError("foreign SecurityIncident row")
        if row.get("TenantId", "").casefold() != workspace.casefold():
            raise ValueError("foreign SecurityIncident workspace")
        at = _time(row.get("TimeGenerated"))
        created = _time(row.get("CreatedTime"))
        modified = _time(row.get("LastModifiedTime"))
        if not beginning <= at <= ending or at < created or modified < created or modified > at:
            raise ValueError("SecurityIncident chronology invalid")
        if previous_at is not None and at <= previous_at:
            raise ValueError("duplicate or unordered SecurityIncident snapshots")
        if created_at is None:
            created_at = created
        elif created != created_at:
            raise ValueError("incident creation identity changed")
        status = row.get("Status")
        if status not in _STATUS:
            raise ValueError("SecurityIncident status invalid")
        if previous_status is not None and previous_status != status:
            # A later snapshot establishes the changed state, not the exact
            # moment when the incident status changed.
            statuses.append({"seen_after": previous_at.isoformat(), "seen_by": at.isoformat(),
                             "from": previous_status, "to": status})
        task_rows = row.get("Tasks")
        if not isinstance(task_rows, list) or len(task_rows) > 1000:
            raise ValueError("SecurityIncident task state unavailable")
        seen = set()
        for task in task_rows:
            if not isinstance(task, dict) or not isinstance(task.get("taskId"), str) or not task["taskId"]:
                raise ValueError("incident task identity invalid")
            tid = task["taskId"]
            if tid in seen or task.get("status") not in _TASK:
                raise ValueError("duplicate or invalid incident task")
            seen.add(tid)
            task_at = _time(task.get("lastModifiedTimeUtc"))
            if not created <= task_at <= at:
                raise ValueError("incident task chronology invalid")
            if tid in task_states and task_states[tid] != task["status"]:
                tasks.append({"task_id": tid, "at": task_at.isoformat(),
                              "from": task_states[tid], "to": task["status"]})
            task_states[tid] = task["status"]
        previous_status, previous_at = status, at
    return {"incident_name": incident_name, "workspace_id": workspace,
            "observed_status_transitions": statuses, "observed_task_transitions": tasks,
            "first_record_at": snapshots[0]["TimeGenerated"], "last_record_at": snapshots[-1]["TimeGenerated"],
            "query_window_start": beginning.isoformat(), "query_window_end": ending.isoformat(),
            "retention_start": retention.isoformat(), "row_count": len(snapshots),
            "baseline_status": snapshots[0]["Status"],
            "triageHistoryComplete": False, "responseProcess": "not_collected",
            "semantics": "Observed SecurityIncident snapshots only; task names and status changes do not prove approved procedure or triage decision"}
