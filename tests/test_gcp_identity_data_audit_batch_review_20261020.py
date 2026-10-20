"""Twelve exact identity/data checks: native responses -> collector -> engine.

Offline witnesses and receipt files are bounded to this cohort's /tmp directory.
Assertions for unsafe PASS counterexamples deliberately remain failing until fixed.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.engine import evaluate_snapshot

SCOPE = "projects/review-project"
NUMBER = "projects/123456789"
KEY = NUMBER + "/locations/global/keys/key-a"
RECEIPTS = Path(os.environ.get("GCP_IDENTITY_REVIEW_RECEIPTS", "/tmp/peasso-gcp-review-20261020/identity_data"))
ACTIVE = "gcp.apikeys.active_service_restrictions"
GEMINI = "gcp.ports.apikeys_api_restricted_with_gemini_api"
AGE = "gcp.ports.iam_api_key_age_90"
APIS = "gcp.ports.iam_api_key_restricts_apis"
CALLERS = "gcp.ports.iam_api_key_restricts_websites_hosts_apps"
BACKEND = "gcp.claude.backend_bucket.bucket_exists"
PERIMETER = "gcp.claude.project.storage_vpc_service_controls"
RETENTION = "gcp.ports.logging_bucket_retention_policy_enabled"
SQL = "gcp.ports.logging_metric_alert_sql_instance_configuration_changes_scoped"
STORAGE = "gcp.ports.logging_metric_alert_storage_iam_permission_changes_scoped"
BACKUP = "gcp_cloudsql_backup_failure_alert"
KMS = "gcp_kms_key_destroy_alert"


@pytest.fixture(autouse=True)
def no_network_or_auth(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline native review forbids sockets, DNS and credentials")
    for field in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, field, forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", forbidden)


def url(host, path):
    return "https://" + host + path


CRM = url("cloudresourcemanager.googleapis.com", "/v3/" + SCOPE)
COMPUTE = url("compute.googleapis.com", "/compute/v1/" + SCOPE)
KEYS = url("apikeys.googleapis.com", "/v2/" + SCOPE + "/locations/global/keys")
SERVICES = url("serviceusage.googleapis.com", "/v1/" + SCOPE + "/services")
BUCKETS = url("storage.googleapis.com", "/storage/v1/b")
SINKS = url("logging.googleapis.com", "/v2/" + SCOPE + "/sinks")
METRICS = url("logging.googleapis.com", "/v2/" + SCOPE + "/metrics")
ALERTS = url("monitoring.googleapis.com", "/v3/" + SCOPE + "/alertPolicies")
POLICIES = url("accesscontextmanager.googleapis.com", "/v1/accessPolicies")
PERIMETERS = url("accesscontextmanager.googleapis.com", "/v1/accessPolicies/9/servicePerimeters")


class NativeAPI:
    def __init__(self, routes, *, scope=SCOPE, denied=(), partial=()):
        self.routes = routes
        self.scope = scope
        self.denied, self.partial = set(denied), set(partial)
        self.evidence, self.requests, self.responses, self.unplanned = [], [], [], []

    def request(self, method, endpoint, **kwargs):
        parsed = urlsplit(endpoint)
        route = (method, parsed.netloc, parsed.path)
        if not (parsed.scheme == "https" and not parsed.query and route in self.routes
                and kwargs["scope"] == self.scope):
            self.unplanned.append({"route": route, "kwargs": kwargs})
            raise AssertionError(self.unplanned[-1])
        rid = "native-" + str(len(self.requests) + 1)
        self.requests.append({"id": rid, "method": method, "url": endpoint, **deepcopy(kwargs)})
        evidence = {"id": rid, "method": method, "url": endpoint, "scope": self.scope,
                    "status": "denied" if endpoint in self.denied else "collected"}
        self.evidence.append(evidence)
        if endpoint in self.denied:
            self.responses.append({"request_id": rid, "url": endpoint, "error": "permission_denied"})
            error = ReadError("denied", "permission_denied", http_status=403)
            error.request_id = rid
            raise error
        response = deepcopy(self.routes[route])
        if endpoint in self.partial:
            response["nextPageToken"] = "unread-page"
        self.responses.append({"request_id": rid, "url": endpoint, "body": deepcopy(response)})
        return response, rid


def observe(label, kinds, ids, responses, *, denied=(), partial=(), selected_scope=SCOPE, mutate=None, **options):
    routes = {}
    common = {
        CRM: {"name": NUMBER, "projectId": "review-project", "state": "ACTIVE"},
        COMPUTE: {"kind": "compute#project", "name": "review-project", "id": "123456789"},
        url("cloudresourcemanager.googleapis.com", "/v1/" + SCOPE + ":getAncestry"):
            {"ancestor": [{"resourceId": {"type": "project", "id": "review-project"}},
                          {"resourceId": {"type": "organization", "id": "34"}}]},
        url("cloudresourcemanager.googleapis.com", "/v3/organizations/34"):
            {"name": "organizations/34", "state": "ACTIVE"},
    }
    for endpoint, response in {**common, **responses}.items():
        endpoint = endpoint.replace(SCOPE, selected_scope)
        parsed = urlsplit(endpoint)
        routes[("POST" if endpoint.endswith(":getAncestry") else "GET", parsed.netloc, parsed.path)] = response
    api = NativeAPI(routes, scope=selected_scope,
        denied=[v.replace(SCOPE, selected_scope) for v in denied],
        partial=[v.replace(SCOPE, selected_scope) for v in partial])
    collector = GCPCollector({"provider": "gcp", "scopes": [selected_scope], "options": {
        "inventories": kinds, "include_inherited": False, "resource_iam": False,
        "metrics_scopes": False, "concurrency": 1, "max_pages": 1, **options}}, transport=api)
    native = collector.collect()
    assert not api.unplanned, api.unplanned
    if mutate is not None:
        from peaso.snapshot import seal
        mutate(native)
        native = seal(native)
    before = deepcopy(native)
    evaluated = evaluate_snapshot(native, checks=list(ids), include_not_applicable=True)
    assert native == before
    findings = [f for f in evaluated["findings"] if f["check_id"] in ids]
    assert findings, evaluated
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    (RECEIPTS / (label + ".json")).write_text(json.dumps({
        "test_nodeid": os.environ["PYTEST_CURRENT_TEST"].rsplit(" (", 1)[0],
        "native_responses": api.responses,
        "requests": api.requests, "snapshot": native, "findings": findings}, indent=2) + "\n")
    return {cid: [f["status"] for f in findings if f["check_id"] == cid] for cid in ids}, native, api


def key_observe(label, cid, restrictions, *, services=None, **kwargs):
    key = {"name": KEY, "createTime": "2026-10-01T00:00:00Z", "restrictions": restrictions}
    responses = {KEYS: {"keys": [key]}}
    kinds = ["api_key"]
    if services is not None:
        kinds += ["service_usage"]
        responses[SERVICES] = {"services": services}
    return observe(label, kinds, [cid], responses, **kwargs)


@pytest.mark.parametrize("state,expected", [("ENABLED", "UNKNOWN"), ("DISABLED", "FAIL"), ("STATE_UNSPECIFIED", "UNKNOWN")])
def test_active_key_services_native_dns_and_alias(state, expected):
    statuses, native, _ = key_observe("active-" + state, ACTIVE,
        {"apiTargets": [{"service": "STORAGE.GOOGLEAPIS.COM"}]},
        services=[{"name": NUMBER + "/services/storage.googleapis.com", "state": state}])
    assert statuses[ACTIVE] == [expected]
    if state != "STATE_UNSPECIFIED":
        key = next(c for c in native["collections"] if c["type"] == "api_key")["items"][0]
        assert key["rawNativeName"] == KEY
        assert key["_provenance"]["derived_project_alias"]["project_identity_source_requests"]


@pytest.mark.parametrize("mode", ["foreign", "denied", "partial", "duplicate", "absent_target"])
def test_active_services_uncertain_evidence_is_never_pass(mode):
    services = [{"name": ("projects/999999999" if mode == "foreign" else NUMBER) + "/services/storage.googleapis.com", "state": "DISABLED"}]
    if mode == "duplicate": services *= 2
    if mode == "absent_target": services = []
    statuses, _, _ = key_observe("active-" + mode, ACTIVE,
        {"apiTargets": [{"service": "storage.googleapis.com"}]}, services=services,
        denied=[SERVICES] if mode == "denied" else (), partial=[SERVICES] if mode == "partial" else ())
    assert statuses[ACTIVE] == ["FAIL" if mode == "duplicate" else "UNKNOWN"]


@pytest.mark.parametrize("targets,expected", [([], "FAIL"), (["storage.googleapis.com"], "PASS"),
    (["cloudapis.googleapis.com"], "FAIL"), (["CLOUDAPIS.GOOGLEAPIS.COM"], "FAIL")])
def test_api_target_restrictions_native_case_insensitive(targets, expected):
    statuses, _, api = key_observe("apis-" + ("upper-" if targets and targets[0].isupper() else "lower-") + (targets[0] if targets else "empty"), APIS,
        {"apiTargets": [{"service": target} for target in targets]})
    assert "keyString" not in next(r for r in api.requests if r["url"] == KEYS)["params"]["fields"]
    assert statuses[APIS] == [expected]


@pytest.mark.parametrize("mode,expected", [("gemini", "PASS"), ("mixed", "FAIL"), ("empty", "FAIL"),
    ("disabled", "PASS"), ("uppercase_mixed", "FAIL"), ("uppercase_wildcard", "FAIL")])
def test_gemini_service_restrictions_native(mode, expected):
    targets = ["generativelanguage.googleapis.com"]
    if mode in ("mixed", "uppercase_mixed"): targets += ["storage.googleapis.com"]
    if mode == "uppercase_mixed": targets[0] = targets[0].upper()
    if mode == "uppercase_wildcard": targets = ["CLOUDAPIS.GOOGLEAPIS.COM"]
    if mode == "empty": targets = []
    statuses, _, _ = key_observe("gemini-" + mode, GEMINI,
        {"apiTargets": [{"service": target} for target in targets]},
        services=[{"name": NUMBER + "/services/generativelanguage.googleapis.com",
                   "state": "DISABLED" if mode == "disabled" else "ENABLED"}])
    assert statuses[GEMINI] == [expected]


@pytest.mark.parametrize("mode,body,expected", [
    ("serverKeyRestrictions", {"allowedIps": ["192.0.2.1"]}, "PASS"),
    ("serverKeyRestrictions", {"allowedIps": ["::/0"]}, "FAIL"),
    ("browserKeyRestrictions", {"allowedReferrers": ["https://example.test/*"]}, "PASS"),
    ("browserKeyRestrictions", {}, "FAIL"),
    ("androidKeyRestrictions", {"allowedApplications": [{"packageName": "com.example.app", "sha1Fingerprint": "00" * 20}]}, "PASS"),
    ("iosKeyRestrictions", {"allowedBundleIds": ["com.example.app"]}, "PASS"),
    ("iosKeyRestrictions", {"allowedBundleIds": None}, "UNKNOWN"),
])
def test_caller_mode_native_allowlists(mode, body, expected):
    statuses, _, _ = key_observe("callers-" + mode + "-" + expected, CALLERS, {mode: body})
    assert statuses[CALLERS] == [expected]


@pytest.mark.parametrize("cid", [AGE, APIS, CALLERS, GEMINI])
@pytest.mark.parametrize("mode", ["denied", "partial"])
def test_key_inventory_uncertainty_never_disappears(cid, mode):
    statuses, _, _ = key_observe("key-" + cid.split(".")[-1] + "-" + mode, cid,
        {"apiTargets": [{"service": "generativelanguage.googleapis.com"}],
         "serverKeyRestrictions": {"allowedIps": ["192.0.2.1"]}},
        services=[{"name": NUMBER + "/services/generativelanguage.googleapis.com", "state": "ENABLED"}] if cid == GEMINI else None,
        denied=[KEYS] if mode == "denied" else (), partial=[KEYS] if mode == "partial" else ())
    assert "PASS" not in statuses[cid] if mode == "denied" else "UNKNOWN" in statuses[cid]


@pytest.mark.parametrize("age_days,expected", [(1, "PASS"), (91, "FAIL"), (90, "FAIL")])
def test_key_age_utc_date_cutoff_native(age_days, expected):
    created = datetime.combine(datetime.now(timezone.utc).date() - timedelta(days=age_days), datetime.min.time(), tzinfo=timezone.utc)
    statuses, _, _ = observe("age-" + str(age_days), ["api_key"], [AGE],
        {KEYS: {"keys": [{"name": KEY, "createTime": created.isoformat()}]}})
    assert statuses[AGE] == [expected]


@pytest.mark.parametrize("cid", [AGE, APIS, CALLERS, GEMINI, ACTIVE])
def test_omitted_key_facts_remain_unknown(cid):
    responses = {KEYS: {"keys": [{"name": KEY}]}}
    kinds = ["api_key"]
    if cid in (GEMINI, ACTIVE):
        kinds.append("service_usage")
        responses[SERVICES] = {"services": [{"name": NUMBER + "/services/generativelanguage.googleapis.com", "state": "ENABLED"}]}
    statuses, _, _ = observe("omitted-" + cid.replace(".", "_"), kinds, [cid], responses)
    assert statuses[cid] == ["UNKNOWN"]


@pytest.mark.parametrize("mode,expected", [("exists", "PASS"), ("absent", "MANUAL"), ("denied", "UNKNOWN"), ("partial", "UNKNOWN")])
def test_backend_bucket_native_project_inventory_is_not_global_absence(mode, expected):
    statuses, _, _ = observe("backend-" + mode, ["backend_bucket", "bucket"], [BACKEND], {
        COMPUTE + "/global/backendBuckets": {"items": [{"name": "backend", "bucketName": "review-assets"}]},
        BUCKETS: {"items": [] if mode == "absent" else [{"name": "review-assets", "projectNumber": "123456789"}]},
        BUCKETS + "/review-assets/iam": {"bindings": []}},
        denied=[BUCKETS] if mode == "denied" else (), partial=[BUCKETS] if mode == "partial" else ())
    assert statuses[BACKEND] == [expected]


@pytest.mark.parametrize("mode,expected", [("enforced", "PASS"), ("dry_run", "FAIL"), ("foreign", "FAIL"),
    ("absent", "FAIL"), ("denied", "UNKNOWN"), ("partial", "UNKNOWN")])
def test_storage_perimeter_native_enforced_resources(mode, expected):
    config = {"resources": ["projects/999999999" if mode == "foreign" else NUMBER],
              "restrictedServices": ["storage.googleapis.com"]}
    perimeter = {"name": "accessPolicies/9/servicePerimeters/p", "perimeterType": "PERIMETER_TYPE_REGULAR",
                 "spec" if mode == "dry_run" else "status": config}
    if mode == "dry_run": perimeter["useExplicitDryRunSpec"] = True
    statuses, _, api = observe("perimeter-" + mode, ["project", "service_perimeter"], [PERIMETER], {
        POLICIES: {"accessPolicies": [{"name": "accessPolicies/9", "parent": "organizations/34"}]},
        PERIMETERS: {"servicePerimeters": [] if mode == "absent" else [perimeter]}},
        denied=[PERIMETERS] if mode == "denied" else (), partial=[PERIMETERS] if mode == "partial" else (),
        include_inherited=True)
    assert next(r for r in api.requests if r["url"] == POLICIES)["params"]["parent"] == "organizations/34"
    assert statuses[PERIMETER] == [expected]


@pytest.mark.parametrize("mode,expected", [("locked", "PASS"), ("unlocked", "FAIL"), ("omitted", "FAIL"),
    ("external", "UNKNOWN"), ("logging", "NOT_APPLICABLE"), ("denied", "UNKNOWN"), ("partial", "UNKNOWN")])
def test_sink_destination_retention_native(mode, expected):
    bucket = {"name": "review-logs", "projectNumber": "123456789"}
    if mode != "omitted": bucket["retentionPolicy"] = {"retentionPeriod": "7776000", "isLocked": mode != "unlocked"}
    destination = "logging.googleapis.com/projects/central/locations/global/buckets/logs" if mode == "logging" else "storage.googleapis.com/review-logs"
    statuses, _, _ = observe("retention-" + mode, ["log_sink", "bucket"], [RETENTION], {
        SINKS: {"sinks": [{"name": "audit", "destination": destination}]},
        BUCKETS: {"items": [] if mode == "external" else [bucket]},
        BUCKETS + "/review-logs/iam": {"bindings": []}},
        denied=[BUCKETS] if mode == "denied" else (), partial=[BUCKETS] if mode == "partial" else ())
    assert statuses[RETENTION] == [expected]


EVENT_FILTERS = {SQL: 'protoPayload.methodName="cloudsql.instances.update"',
    STORAGE: 'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"',
    KMS: 'protoPayload.methodName="DestroyCryptoKeyVersion"',
    BACKUP: 'resource.type="cloudsql_database" AND protoPayload.methodName="cloudsql.instances.automatedBackup" AND protoPayload.metadata.windowStatus="STATUS_FAILED"'}


def alert_observe(cid, mode, *, project_id_scope=False, crm=None, mutate=None,
                  denied_project=False, numeric_policy=False):
    selected_scope = SCOPE if cid != BACKUP or project_id_scope else NUMBER
    metric = {"name": "events", "filter": EVENT_FILTERS[cid],
              "metricDescriptor": {"type": "logging.googleapis.com/user/events", "metricKind": "DELTA", "valueType": "INT64"}}
    threshold = {"filter": 'metric.type="logging.googleapis.com/user/events"',
                 "comparison": "COMPARISON_GT", "thresholdValue": 0, "duration": "0s"}
    if cid in (SQL, BACKUP): threshold["filter"] += ' AND resource.type="cloudsql_database"'
    if cid == STORAGE: threshold["filter"] += ' AND resource.type="gcs_bucket"'
    if cid == KMS: threshold["filter"] += ' AND resource.type="cloudkms_cryptokeyversion"'
    policy = {"name": selected_scope + "/alertPolicies/alert", "enabled": True, "combiner": "OR",
              "notificationChannels": [], "conditions": [{"conditionThreshold": threshold}]}
    if numeric_policy: policy["name"] = NUMBER + "/alertPolicies/alert"
    if mode == "disabled": policy["enabled"] = False
    if mode == "invalid": policy["validity"] = {"code": 3, "message": "Invalid condition"}
    if mode == "foreign": policy["name"] = "projects/other-project/alertPolicies/alert"
    label = "bucket_name" if cid == STORAGE else "database_id"
    if mode == "restricted_metric": metric["filter"] += f' AND resource.labels.{label}="only-one"'
    if mode == "restricted_series": threshold["filter"] += f' AND resource.labels.{label}="only-one"'
    if mode == "impossible_threshold": threshold.update(comparison="COMPARISON_LT", thresholdValue=-1)
    if mode == "direct": policy["conditions"] = [{"conditionMatchedLog": {"filter": EVENT_FILTERS[cid]}}]
    if mode == "and_combiner":
        policy["combiner"] = "AND"
        # Both conditions reference the real native counter, but the second
        # condition cannot hold for its nonnegative DELTA INT64 counts.
        policy["conditions"].append({"conditionThreshold": {**threshold,
            "comparison": "COMPARISON_LT", "thresholdValue": -1}})
    responses = {METRICS: {"metrics": [] if mode in ("absent", "direct") else [metric]},
                 ALERTS: {"alertPolicies": [] if mode == "absent" else [policy]}}
    if crm is not None: responses[CRM] = crm
    statuses, native, api = observe("alert-" + cid.replace(".", "_") + "-" + mode + ("-project-id" if project_id_scope else "")
        + ("-" + os.environ["PYTEST_CURRENT_TEST"].split("[", 1)[-1].split("]", 1)[0] if mutate or crm is not None or denied_project or numeric_policy else ""),
        ["alert_policy", "logging_metric"] if cid == KMS else ["project", "logging_metric", "monitoring_alert_policy"], [cid],
        responses, denied=([ALERTS] if mode == "denied" else []) + ([CRM] if denied_project else []),
        partial=[ALERTS] if mode == "partial" else (), selected_scope=selected_scope, mutate=mutate)
    assert "validity" in next(r for r in api.requests if r["url"] == ALERTS.replace(SCOPE, selected_scope))["params"]["fields"]
    return statuses[cid], native


@pytest.mark.parametrize("cid", [SQL, STORAGE, BACKUP, KMS])
@pytest.mark.parametrize("mode,expected", [("complete", "PASS"), ("absent", "FAIL"), ("disabled", "FAIL"),
    ("denied", "UNKNOWN"), ("partial", "UNKNOWN")])
def test_alert_native_baseline_and_inventory_coverage(cid, mode, expected):
    statuses, _ = alert_observe(cid, mode)
    assert statuses == [expected]


@pytest.mark.parametrize("cid", [SQL, STORAGE, KMS])
@pytest.mark.parametrize("mode", ["invalid", "restricted_metric", "restricted_series", "impossible_threshold", "and_combiner", "foreign"])
def test_alert_counterexamples_must_not_pass(cid, mode):
    statuses, _ = alert_observe(cid, mode)
    assert "PASS" not in statuses, (cid, mode, statuses)


@pytest.mark.parametrize("mode,expected", [("direct", "PASS"), ("invalid", "FAIL"),
    ("restricted_metric", "UNKNOWN"), ("restricted_series", "UNKNOWN"),
    ("impossible_threshold", "UNKNOWN"), ("and_combiner", "UNKNOWN"), ("foreign", "UNKNOWN")])
def test_backup_supported_native_contract_remains_conservative(mode, expected):
    statuses, _ = alert_observe(BACKUP, mode)
    assert statuses == [expected]


@pytest.mark.parametrize("mode,expected", [("complete", "PASS"), ("absent", "FAIL"), ("invalid", "FAIL"), ("direct", "PASS")])
def test_backup_project_id_scope_accepts_authoritative_numeric_crm_identity(mode, expected):
    statuses, _ = alert_observe(BACKUP, mode, project_id_scope=True)
    assert statuses == [expected]


@pytest.mark.parametrize("cid", [APIS, GEMINI])
@pytest.mark.parametrize("service,expected", [("STORAGE.GOOGLEAPIS.COM", "PASS"),
    ("ClOuDaPiS.GoOgLeApIs.CoM", "FAIL"), ("", "UNKNOWN"),
    ("storage.googleapis.com ", "UNKNOWN"), ("invalid..googleapis.com", "UNKNOWN"),
    (None, "UNKNOWN")])
def test_api_target_canonicalization_preserves_unknown(cid, service, expected):
    statuses, _, _ = key_observe("target-validation-" + cid.split(".")[-1] + "-" + str(service), cid,
        {"apiTargets": [{"service": service}]},
        services=[{"name": NUMBER + "/services/generativelanguage.googleapis.com", "state": "ENABLED"}] if cid == GEMINI else None)
    assert statuses[cid] == [expected]


@pytest.mark.parametrize("mode", ["direct", "complete"])
def test_backup_project_id_scope_accepts_numeric_policy_name(mode):
    statuses, _ = alert_observe(BACKUP, mode, project_id_scope=True, numeric_policy=True)
    assert statuses == ["PASS"]


@pytest.mark.parametrize("mode", ["denied", "foreign_id", "missing_id", "malformed_name", "foreign_numeric_scope"])
def test_backup_project_alias_unbound_native_identity_stays_unknown(mode):
    project = {"name": NUMBER, "projectId": "review-project", "state": "ACTIVE"}
    if mode == "foreign_id": project["projectId"] = "other-project"
    if mode == "missing_id": project.pop("projectId")
    if mode == "malformed_name": project["name"] = "projects/not-numeric"
    if mode == "foreign_numeric_scope": project["name"] = "projects/999999999"
    statuses, _ = alert_observe(BACKUP, "direct", project_id_scope=mode != "foreign_numeric_scope",
        crm=project, denied_project=mode == "denied")
    assert statuses and set(statuses) == {"DENIED" if mode == "denied" else "UNKNOWN"}


@pytest.mark.parametrize("mode", ["denied_field", "missing_receipt", "denied_receipt", "foreign_receipt", "wrong_endpoint",
    "stale", "foreign_provenance", "missing_refs", "duplicate_project", "partial_project", "wrong_native_id"])
def test_backup_project_alias_unproven_provenance_stays_unknown(mode):
    def mutate(native):
        envelope = next(c for c in native["collections"] if c["type"] == "project" and c["scope"] == SCOPE)
        project = envelope["items"][0]
        proof = project["_provenance"]
        ledger = native["metadata"]["source_requests"]
        receipt = next(r for r in ledger if r["url"] == CRM)
        if mode == "denied_field": project.setdefault("_coverage", {})["projectId"] = {"status": "denied"}
        if mode == "missing_receipt": ledger.remove(receipt)
        if mode == "denied_receipt": receipt["status"] = "denied"
        if mode == "foreign_receipt": receipt["scope"] = "projects/other-project"
        if mode == "wrong_endpoint": receipt["url"] = CRM.replace("/v3/", "/v1/")
        if mode == "stale": proof["collected_at"] = "2000-01-01T00:00:00Z"
        if mode == "foreign_provenance": proof["scope"] = "projects/other-project"
        if mode == "missing_refs": proof["source_requests"] = []
        if mode == "duplicate_project": envelope["items"].append(deepcopy(project))
        if mode == "partial_project": envelope.update(status="partial", coverage_status="partial")
        if mode == "wrong_native_id": project["native_id"] = "projects/999999999"
    statuses, _ = alert_observe(BACKUP, "direct", project_id_scope=True, mutate=mutate)
    assert statuses and set(statuses) == {"UNKNOWN"}
