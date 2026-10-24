"""Complete IAM service use evidence with the scan's own authenticated contexts."""
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from concurrent.futures import ThreadPoolExecutor
import copy
import time

from peaso.snapshot import make_snapshot

_active = ContextVar("aws_iam_usage_contexts", default=None)


@contextmanager
def capture_contexts(enabled=True):
    contexts = {} if enabled else None
    token = _active.set(contexts)
    try:
        yield contexts
    finally:
        _active.reset(token)


def register_context(requests, session, identity, regions):
    contexts = _active.get()
    account = identity.get("Account") if isinstance(identity, dict) else None
    if contexts is not None and account and regions:
        contexts.setdefault(account, (requests, session, regions[0]))
        requests.iam_usage_scan = True
    return contexts is not None


def enrich_snapshot(snapshot, contexts):
    from .aws_iam_report_native import service_reports

    if contexts is None:
        return snapshot
    collections = copy.deepcopy(snapshot["collections"])
    by_account = {}
    for collection in collections:
        if collection.get("type") not in {"iam_user", "iam_group", "iam_role", "iam_policy"}:
            continue
        if collection.get("status") not in {"collected", "partial"}:
            continue
        for item in collection.get("items", []):
            arn = item.get("Arn") if isinstance(item, dict) else None
            if not isinstance(arn, str) or ":iam::" not in arn:
                continue
            account = arn.split(":")[4]
            if account not in contexts:
                continue
            if collection["type"] == "iam_policy" and not item.get("AttachmentCount", 0):
                continue
            state = item.get("ServicesLastAccessedStatus", {})
            deferred = state.get("reason") == "identity_policies_cannot_allow_namespaces" or (
                state.get("error") or {}).get("code") == "service_last_accessed_generation_disabled"
            if state and not deferred and not (state.get("collection_status") == "collected"
                                                 and state.get("granularity") != "ACTION_LEVEL"):
                continue
            by_account.setdefault(account, {}).setdefault(arn, []).append(item)
    def report_for(account, items):
        requests, session, region = contexts[account]
        requests.iam_report_generation_requested = True
        requests.iam_service_access_reports_requested = True
        requests.service_last_accessed_wait = max(requests.service_last_accessed_wait, 600)
        requests.service_last_accessed_workers = max(requests.service_last_accessed_workers, 8)
        with requests._lock:
            deadlines = getattr(requests, "_sla_batch_deadlines", None)
            if deadlines is None:
                deadlines = requests._sla_batch_deadlines = {}
            deadlines[(id(session), region)] = time.monotonic() + requests.service_last_accessed_wait
        return service_reports(requests, session, region, items.keys(), granularity="ACTION_LEVEL")

    accounts = list(by_account)
    # Requests keeps global call/page/resource limits, while its IAM report
    # pacing and job bindings are keyed by session. Preserve admission order
    # whenever a limit is explicit or two accounts share a session.
    independent = (len(accounts) > 1
        and len({id(contexts[account][1]) for account in accounts}) == len(accounts)
        and all(getattr(contexts[account][0], limit, None) is None
                for account in accounts for limit in ("max_calls", "max_pages", "max_items")))

    def apply_reports(account, account_reports):
        items = by_account[account]
        for arn, (rows, status) in account_reports.items():
            for item in items[arn]:
                if rows is not None:
                    item["ServicesLastAccessed"] = rows
                item["ServicesLastAccessedStatus"] = status

    if independent:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="aws-iam-usage") as pool:
            futures = [pool.submit(copy_context().run, report_for, account, by_account[account])
                       for account in accounts]
            # Apply in stable account order and release each large report once
            # used. Executor exit joins every account even if one raises.
            for index, account in enumerate(accounts):
                apply_reports(account, futures[index].result())
                futures[index] = None
    else:
        for account in accounts:
            apply_reports(account, report_for(account, by_account[account]))
    if not by_account:
        return snapshot
    return make_snapshot(snapshot["provider"], snapshot["scopes"], collections,
                         created_at=snapshot["created_at"], metadata=snapshot.get("metadata"))
