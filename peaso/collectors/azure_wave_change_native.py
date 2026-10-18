"""Pure checks for Azure Activity Log collection coverage.

The ARM Activity Logs List response proves events only for the query window that
was actually requested.  This module never manufactures approval or change rows.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


class ActivityCoverageError(ValueError):
    """The captured Activity Log cannot prove the requested review window."""


def _instant(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise ActivityCoverageError("Activity Log window timestamp missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ActivityCoverageError("Activity Log window timestamp invalid") from exc
    if result.tzinfo is None:
        raise ActivityCoverageError("Activity Log window timestamp lacks timezone")
    return result.astimezone(timezone.utc)


def validate_activity_window(index: dict, scope: str, start: str, end: str, *, end_inclusive=False) -> int:
    """Require one complete native ARM read covering [start, end).

    Returns the number of distinct collected events.  An empty collection is
    valid coverage, though a caller may still require independent proof that
    the relevant business change inventory is complete.
    """
    begin, finish = _instant(start), _instant(end)
    if begin >= finish:
        raise ActivityCoverageError("Activity Log review window invalid")
    collections = index.get("collections")
    rows = collections.get("activity_log") if isinstance(collections, dict) else None
    if not isinstance(rows, list) or len(rows) != 1:
        raise ActivityCoverageError("Activity Log collection missing or ambiguous")
    collection = rows[0]
    actual_scope = collection.get("scope") if isinstance(collection, dict) else None
    if (not isinstance(scope, str) or not isinstance(actual_scope, str)
            or collection.get("type") != "activity_log"
            or actual_scope.casefold() != scope.casefold()):
        raise ActivityCoverageError("Activity Log collection scope invalid")
    items = collection.get("items")
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ActivityCoverageError("Activity Log items malformed")
    if collection.get("status") != ("collected" if items else "empty"):
        raise ActivityCoverageError("Activity Log collection incomplete")
    window = collection.get("queryWindow")
    if not isinstance(window, dict) or window.get("endExclusive") is not True:
        raise ActivityCoverageError("Activity Log native query window unavailable")
    query_end = _instant(window.get("end"))
    if (_instant(window.get("start")) > begin or query_end < finish
            or end_inclusive and query_end == finish):
        raise ActivityCoverageError("Activity Log query window does not cover review window")
    seen = set()
    for item in items:
        event_id = item.get("id")
        if not isinstance(event_id, str) or not event_id or event_id in seen:
            raise ActivityCoverageError("Activity Log event identity missing or duplicate")
        seen.add(event_id)
    return len(seen)


def validate_native_activity_if_present(index: dict, scope: str, start: str, end: str, *, end_inclusive=False) -> int | None:
    """Check a native ARM read; leave a separate approved import to its contract.

    Native ``azure.py`` sets ``queryWindow`` on the Activity Log collection.
    Existing imported evidence uses a separate coverage record and has no
    native query metadata.  ``None`` means this native check was not applicable;
    it is never positive evidence about an import's completeness or authority.
    """
    collections = index.get("collections")
    rows = collections.get("activity_log") if isinstance(collections, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ActivityCoverageError("Activity Log collection missing or ambiguous")
    if "queryWindow" not in rows[0]:
        return None
    return validate_activity_window(index, scope, start, end, end_inclusive=end_inclusive)


def derive_native_activity_coverage(index: dict, scope: str, captured_at: str) -> dict:
    """Project bounded native list completion into the existing coverage ABI.

    Azure's default Activity Log retention is 90 days.  A query beginning
    earlier cannot support a complete-window claim from this endpoint.  This
    row records query coverage only, never approval or change history.
    """
    collections = index.get("collections")
    rows = collections.get("activity_log") if isinstance(collections, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ActivityCoverageError("Activity Log collection missing or ambiguous")
    window = rows[0].get("queryWindow")
    if not isinstance(window, dict):
        raise ActivityCoverageError("Activity Log native query window unavailable")
    start, end = window.get("start"), window.get("end")
    count = validate_activity_window(index, scope, start, end)
    captured = _instant(captured_at)
    if _instant(start) < captured - timedelta(days=90) or _instant(end) > captured:
        raise ActivityCoverageError("Activity Log native retention or capture window unresolved")
    return {"id": scope, "retainedFrom": start, "collectedThrough": end,
            "_provenance": {"authority": "Azure.ActivityLogs:List",
                            "api_version": "2015-04-01", "read_only": True,
                            "captured_at": captured_at, "event_count": count,
                            "basis": "complete native query window within documented 90-day retention"}}


def collect(reader, scopes, wanted, instant=None):
    """Reuse completed ARM list reads; never infer approval or business history."""
    if 'activity_log_coverage' not in wanted:
        return
    captured_at = instant or datetime.now(timezone.utc).isoformat()
    jobs = []
    for scope in scopes:
        sources = [c for c in reader.collections if c.get('type') == 'activity_log'
                   and str(c.get('scope', '')).casefold() == scope.casefold()]
        if len(sources) == 1 and sources[0].get('status') not in ('collected', 'empty'):
            source = sources[0]
            envelope = {'type': 'activity_log_coverage', 'scope': scope,
                'service': 'Microsoft.Insights', 'status': source['status'], 'items': []}
            if 'error' in source:
                envelope['error'] = dict(source['error'])
            with reader.lock:
                reader.collections.append(envelope)
            reader.progress(scope=scope, settled=envelope)
            continue
        def fetch(scope=scope):
            sources = [c for c in reader.collections if c.get('type') == 'activity_log'
                       and str(c.get('scope', '')).casefold() == scope.casefold()]
            if len(sources) != 1 or sources[0].get('service') != 'Microsoft.Insights':
                raise ValueError('native Activity Log source unavailable or ambiguous')
            source = sources[0]
            proof = source.get('native_query_provenance')
            if (not isinstance(proof, dict) or proof.get('read_only') is not True
                    or proof.get('source_operation') != 'ActivityLogs_List'
                    or proof.get('api_version') != '2015-04-01'):
                raise ValueError('native Activity Log query source unproven')
            window = source.get('queryWindow', {})
            begin = datetime.fromisoformat(window['start'].replace('Z', '+00:00'))
            end = datetime.fromisoformat(window['end'].replace('Z', '+00:00'))
            for event in source.get('items', []):
                resource = event.get('resourceId')
                if (not isinstance(resource, str) or not (resource.casefold() == scope.casefold()
                        or resource.casefold().startswith(scope.casefold() + '/'))):
                    raise ValueError('Activity Log event outside selected subscription')
                timestamp = event.get('eventTimestamp')
                if not isinstance(timestamp, str):
                    raise ValueError('Activity Log event time unavailable')
                observed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if observed.tzinfo is None or not begin <= observed < end:
                    raise ValueError('Activity Log event outside native query window')
            index = {'collections': {'activity_log': sources}}
            yield [derive_native_activity_coverage(index, scope, captured_at)]
        jobs.append(('activity_log_coverage', scope, 'Microsoft.Insights', fetch))
    reader.run(jobs)


