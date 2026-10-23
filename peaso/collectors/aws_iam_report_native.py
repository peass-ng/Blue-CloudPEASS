"""Selection-gated IAM Read-classified report jobs; no IAM configuration changes."""
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import csv
import io
import re
import time

LAST_ACCESSED_FIELDS = ("ServiceNamespace", "ServiceName", "LastAuthenticated", "LastAuthenticatedRegion", "TotalAuthenticatedEntities")
UNAVAILABLE_REPORT_CODES = {"ReportNotPresent", "ReportExpired", "ReportInProgress", "CredentialReportNotPresent", "CredentialReportExpired", "CredentialReportNotReady"}

def service_reports(requests, session, region, arns):
    """Bounded IAM Read-classified report jobs, bound to this session and ARN.

    Reports describe attempts and observation history, not effective access.
    No externally supplied job identifier is accepted.
    """
    from .aws import ReadFailure, _failure, _safe
    if not getattr(requests, "iam_service_access_reports_requested", False):
        return {arn: (None, {"collection_status": "not_collected", "operation": "iam:GetServiceLastAccessedDetails",
            "granularity": "SERVICE_LEVEL", "error": {"code": "service_last_accessed_generation_disabled"}}) for arn in sorted(arns)}
    with requests._lock:
        job_bindings = getattr(requests, "_sla_job_bindings", None)
        if job_bindings is None:
            job_bindings = requests._sla_job_bindings = {}
    ordered = sorted(set(arns))
    if not ordered:
        return {}
    try:
        # Same Requests cache key/session as public collection authentication.
        identity = requests.call(session, "sts", region, "get_caller_identity")
        account, caller_arn = identity.get("Account"), identity.get("Arn")
        partition = session.get_partition_for_region(region)
        if (not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None
                or not isinstance(caller_arn, str) or re.fullmatch(r"arn:" + re.escape(partition) + r":(?:iam|sts)::" + account + r":.+", caller_arn) is None):
            raise ReadFailure("malformed", "service_report_caller_identity_invalid")
    except Exception as exc:
        failure = _failure(exc)
        return {arn: (None, {"collection_status": failure.status, "error": {"code": failure.code}}) for arn in ordered}
    with requests._lock:
        deadlines = getattr(requests, "_sla_batch_deadlines", None)
        if deadlines is None:
            deadlines = requests._sla_batch_deadlines = {}
        deadline = deadlines.setdefault((id(session), region), time.monotonic() + requests.service_last_accessed_wait)

    def one(arn):
        state = {"collection_status": "unknown", "operation": "iam:GetServiceLastAccessedDetails",
                 "granularity": "SERVICE_LEVEL", "principal_arn": arn,
                 "semantics": "IAM service-access attempt history; effective permissions unassessed"}
        try:
            partition = session.get_partition_for_region(region)
            match = re.fullmatch(r"arn:" + re.escape(partition) + r":iam::([0-9]{12}):(user|role|policy)/.+", arn)
            if match is None or match.group(1) != account:
                raise ReadFailure("malformed", "service_report_principal_arn_invalid")
            requests.check_deadline()
            if time.monotonic() >= deadline:
                raise ReadFailure("timeout", "service_report_batch_timeout")
            generated = requests.call(session, "iam", region, "generate_service_last_accessed_details",
                                      Arn=arn, Granularity="SERVICE_LEVEL")
            job = generated.get("JobId")
            if not isinstance(job, str) or not re.fullmatch(r"[A-Za-z0-9-]{36}", job):
                raise ReadFailure("malformed", "service_report_job_id_invalid")
            binding = (id(session), region, job)
            with requests._lock:
                if binding in job_bindings and job_bindings[binding] != arn:
                    raise ReadFailure("malformed", "service_report_job_id_reused")
                job_bindings[binding] = arn
            response = None
            for poll in range(60):
                requests.check_deadline()
                if time.monotonic() >= deadline:
                    raise ReadFailure("timeout", "service_report_poll_timeout")
                response = requests.call(session, "iam", region, "get_service_last_accessed_details",
                                         _cache_refresh=True, JobId=job)
                status = response.get("JobStatus")
                if status == "COMPLETED":
                    break
                if status == "FAILED":
                    raise ReadFailure("unknown", "service_report_job_failed")
                if status != "IN_PROGRESS":
                    raise ReadFailure("malformed", "service_report_job_status_invalid")
                requests._sleep(min(1, max(0, deadline - time.monotonic())))
            else:
                raise ReadFailure("timeout", "service_report_poll_limit")
            rows, namespaces, markers = [], set(), set()
            signature, page = None, 0
            while True:
                requests.check_deadline()
                if time.monotonic() >= deadline:
                    raise ReadFailure("timeout", "service_report_page_timeout")
                page += 1
                if requests.max_pages is not None and page > requests.max_pages:
                    raise ReadFailure("partial", "service_report_page_limit")
                created, completed = response.get("JobCreationDate"), response.get("JobCompletionDate")
                if (response.get("JobStatus") != "COMPLETED" or response.get("JobType") != "SERVICE_LEVEL"
                        or not isinstance(created, datetime) or created.tzinfo is None
                        or not isinstance(completed, datetime) or completed.tzinfo is None or completed < created
                        or not isinstance(response.get("ServicesLastAccessed"), list)
                        or type(response.get("IsTruncated")) is not bool):
                    raise ReadFailure("malformed", "service_report_completed_page_invalid")
                current = (created, completed, response["JobType"])
                if signature is not None and current != signature:
                    raise ReadFailure("malformed", "service_report_page_identity_mismatch")
                signature = current
                for entry in response["ServicesLastAccessed"]:
                    namespace = entry.get("ServiceNamespace") if isinstance(entry, dict) else None
                    if (not isinstance(namespace, str) or not namespace or namespace in namespaces
                            or not isinstance(entry.get("ServiceName"), str) or not entry["ServiceName"]):
                        raise ReadFailure("malformed", "service_report_service_identity_invalid")
                    if "LastAuthenticated" in entry and (not isinstance(entry["LastAuthenticated"], datetime) or entry["LastAuthenticated"].tzinfo is None or entry["LastAuthenticated"] > completed):
                        raise ReadFailure("malformed", "service_report_last_authenticated_invalid")
                    namespaces.add(namespace)
                    rows.append(_safe({field: entry[field] for field in LAST_ACCESSED_FIELDS if field in entry}))
                if not response["IsTruncated"]:
                    break
                marker = response.get("Marker")
                if not isinstance(marker, str) or not marker or marker in markers:
                    raise ReadFailure("malformed", "service_report_cursor_invalid")
                markers.add(marker)
                if requests.max_pages is not None and page >= requests.max_pages:
                    raise ReadFailure("partial", "service_report_page_limit")
                response = requests.call(session, "iam", region, "get_service_last_accessed_details", JobId=job, Marker=marker)
            state.update(collection_status="collected", job_id=job, source_operation="iam:GenerateServiceLastAccessedDetails",
                         job_creation_date=_safe(created), job_completion_date=_safe(completed), pages=page)
            return arn, (rows, state)
        except Exception as exc:
            failure = _failure(exc)
            state.update(collection_status=failure.status, error={"code": failure.code})
            return arn, (None, state)

    with ThreadPoolExecutor(max_workers=min(requests.service_last_accessed_workers, len(ordered))) as pool:
        return dict(pool.map(one, ordered))


def credential_report(requests, session, region):
    from .aws import ReadResult, ReadFailure, _single, _failure, _safe
    read = _single(requests, session, region, 'iam', 'get_credential_report', absent=UNAVAILABLE_REPORT_CODES)
    missing = read.status == 'empty' and read.error and read.error.get('code') in UNAVAILABLE_REPORT_CODES
    if missing and not getattr(requests, 'iam_credential_report_generation_requested', False):
        return ReadResult([], 'not_collected', {'code': 'credential_report_generation_disabled', 'source_code': read.error['code']})
    if missing:
        try:
            deadline = time.monotonic() + requests.evidence_generation_wait
            for poll in range(60):
                requests.check_deadline()
                if time.monotonic() >= deadline:
                    raise ReadFailure('timeout', 'credential_report_poll_timeout')
                generated = requests.call(session, 'iam', region, 'generate_credential_report', _cache_refresh=True)
                state = generated.get('State')
                if state == 'COMPLETE':
                    read = _single(requests, session, region, 'iam', 'get_credential_report', _cache_refresh=True,
                                   absent=UNAVAILABLE_REPORT_CODES)
                    if read.status == 'empty':
                        return ReadResult([], 'not_collected', {'code': 'credential_report_unavailable_after_generation'})
                    break
                if state not in ('STARTED', 'INPROGRESS'):
                    raise ReadFailure('malformed', 'credential_report_generation_state_invalid')
                requests._sleep(min(1, max(0, deadline-time.monotonic())))
            else:
                raise ReadFailure('timeout', 'credential_report_poll_limit')
        except Exception as exc:
            failure = _failure(exc)
            return ReadResult([], failure.status, {'code': failure.code})
    if read.items:
        response = read.items[0]
        content = response.get('Content')
        if not isinstance(content, bytes) or response.get('ReportFormat') != 'text/csv':
            return ReadResult([], 'malformed', {'code': 'malformed_credential_report'})
        try:
            read.items = list(csv.DictReader(io.StringIO(content.decode('utf-8'))))
            if any(not row.get('user') or None in row for row in read.items):
                raise ValueError('malformed CSV')
            for row in read.items:
                row['ReportGeneratedTime'] = _safe(response.get('GeneratedTime'))
            read.status = 'collected' if read.items else 'empty'
        except (ValueError, UnicodeError):
            return ReadResult([], 'malformed', {'code': 'malformed_credential_report'})
    return read
