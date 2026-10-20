"""claude2_gcp: Cloud Functions, Cloud Run, API key, BigQuery and Cloud SQL predicates.

Declared configuration only. Missing, denied or malformed facts are UNKNOWN; joins across inventories
require complete scoped inventories and a unique match.
"""
from __future__ import annotations

from .claude2_gcp_common import (gcp, cid, cases, scope_index, public_bindings, captured_at, parse_time, result, get, optional,
                                 list_of_objects, complete_items, Unavailable)

SERVICE_IDS = []
INGRESS = ("ALLOW_ALL", "ALLOW_INTERNAL_ONLY", "ALLOW_INTERNAL_AND_GCLB")
# Predefined roles whose permissions include run.routes.invoke on a service.
RUN_INVOKE_ROLES = ("roles/run.invoker", "roles/run.servicesInvoker")


def track(slug):
    SERVICE_IDS.append(cid(slug))
    return cid(slug)


def deleting(function):
    state = optional(function, "state", None, str)
    if state == "DELETING":
        return "NOT_APPLICABLE", {"reason": "Function is being deleted", "state": state}
    return None


# --- Cloud Functions -----------------------------------------------------------------------------------------

@gcp("function.ingress_not_allow_all", "function", "Cloud Function ingress settings do not allow all traffic", control="SC-7",
     category="exposure", remediation="Set the function ingress setting to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB "
                                       "(gcloud functions deploy --ingress-settings=internal-only).")
def function_ingress(function, index):
    skip = deleting(function)
    if skip:
        return skip
    setting = get(function, "serviceConfig.ingressSettings", str)
    if setting not in INGRESS:
        raise Unavailable("unrecognized ingress setting")
    return result(setting == "ALLOW_ALL", ingress_settings=setting)


cases(track("function.ingress_not_allow_all"), {"serviceConfig": {"ingressSettings": "ALLOW_INTERNAL_ONLY"}},
      {"serviceConfig": {"ingressSettings": "ALLOW_ALL"}}, unknown={"serviceConfig": {"ingressSettings": "INGRESS_SETTINGS_UNSPECIFIED"}},
      not_applicable={"state": "DELETING", "serviceConfig": {"ingressSettings": "ALLOW_ALL"}},
      malformed={"serviceConfig": {}})


def _service_suffix(name):
    parts = name.split("/")
    if (len(parts) != 6 or parts[0] != "projects" or parts[2] != "locations" or parts[4] != "services"
            or any(not part or part != part.strip() for part in parts)):
        raise Unavailable("malformed Cloud Run service name")
    return "/".join(parts[2:])


def backing_service(function, index):
    """The Cloud Run service behind a 2nd-gen function, from the complete scoped inventory."""
    name = get(function, "serviceConfig.service", str)
    suffix = _service_suffix(name)
    services = complete_items(index, "cloudrun_service")
    names = [get(service, "name", str) for service in services]
    for candidate in names:
        _service_suffix(candidate)
    scope = get(index, "context.scope", str)
    if not scope.startswith("projects/") or len(scope.split("/")) != 2:
        raise Unavailable("function project scope unavailable")
    aliases = {scope.split("/")[1]}
    parents = {value.split("/")[1] for value in [name, *names]}
    if not parents <= aliases:
        projects = complete_items(index, "project")
        if len(projects) != 1:
            raise Unavailable("native project alias identity absent or ambiguous")
        project = projects[0]
        project_id = get(project, "projectId", str)
        number_name = get(project, "name", str)
        if (not number_name.startswith("projects/") or not number_name.removeprefix("projects/").isascii()
                or not number_name.removeprefix("projects/").isdigit()
                or get(project, "_provenance.scope", str) != scope
                or not get(project, "_provenance.source_requests", list)
                or scope not in ("projects/" + project_id, number_name)):
            raise Unavailable("native project alias identity is not bound to function scope")
        aliases.update((project_id, number_name.removeprefix("projects/")))
    if not parents <= aliases:
        raise Unavailable("backing Cloud Run service belongs to another project")
    rows = [service for service, candidate in zip(services, names) if _service_suffix(candidate) == suffix]
    if len(rows) != 1:
        raise Unavailable("backing Cloud Run service absent or ambiguous")
    return rows[0]


def run_exposure(service):
    """('FAIL'|'MANUAL'|'PASS', evidence) for public invocation of a Cloud Run service."""
    if optional(service, "invokerIamDisabled", False, bool):
        return "FAIL", {"invoker_iam_disabled": True}
    public = public_bindings(get(service, "iamPolicy", dict))
    invoke = [b for b in public if b["role"] in RUN_INVOKE_ROLES and not b["conditional"]]
    if invoke:
        return "FAIL", {"public_invoker_bindings": invoke}
    if public:
        return "MANUAL", {"public_bindings": public,
                          "reason": "Public member holds a conditional or non-invoker role; review whether it grants invocation"}
    return "PASS", {"public_bindings": []}


@gcp("function.not_publicly_accessible", "function", "Cloud Function is not publicly accessible or invocable", severity="high",
     control="AC-3", category="exposure", dependencies=["function", "cloudrun_service", "project"],
     remediation="Remove allUsers and allAuthenticatedUsers from the function IAM policy and, for 2nd-gen functions, from the "
                 "roles/run.invoker binding of the backing Cloud Run service.")
def function_public(function, index):
    skip = deleting(function)
    if skip:
        return skip
    public = public_bindings(get(function, "iamPolicy", dict))
    if any(not b["conditional"] for b in public):
        return result(True, function_public_bindings=public)
    environment = get(function, "environment", str)
    if environment not in ("GEN_1", "GEN_2"):
        raise Unavailable("unrecognized function environment")
    evidence = {"function_public_bindings": public, "environment": environment}
    status = "PASS"
    if environment == "GEN_2":
        service = backing_service(function, index)
        status, service_evidence = run_exposure(service)
        evidence.update(service=service["name"], **service_evidence)
    if status == "FAIL":
        return result(True, **evidence)
    if status == "MANUAL" or public:
        return "MANUAL", {**evidence, "reason": evidence.get("reason", "Conditional public binding on the function")}
    return result(False, **evidence)


_RUN = "projects/p/locations/us-central1/services/fn"
_PRIVATE = {"bindings": [{"role": "roles/run.invoker", "members": ["serviceAccount:caller@p.iam.gserviceaccount.com"]}]}
_OPEN = {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}
_G2 = {"environment": "GEN_2", "serviceConfig": {"service": _RUN}, "iamPolicy": {"bindings": []}}
cases(track("function.not_publicly_accessible"), _G2, _G2,
      pass_index=scope_index({"cloudrun_service": [{"name": _RUN, "iamPolicy": _PRIVATE}]}),
      fail_index=scope_index({"cloudrun_service": [{"name": _RUN, "iamPolicy": _OPEN}]}),
      manual=_G2, manual_index=scope_index({"cloudrun_service": [{"name": _RUN, "iamPolicy": {"bindings": [
          {"role": "roles/run.viewer", "members": ["allAuthenticatedUsers"]}]}}]}),
      unknown=_G2, unknown_index=scope_index({"cloudrun_service": []}),
      not_applicable={**_G2, "state": "DELETING"},
      malformed={"environment": "GEN_1", "iamPolicy": {"bindings": [{"role": "roles/cloudfunctions.invoker", "members": "allUsers"}]}})


@gcp("function.vpc_connector_configured", "function", "Cloud Function egress uses a Serverless VPC Access connector",
     control="SC-7", category="hardening", dependencies=["function", "cloudrun_service", "project"],
     remediation="Attach a Serverless VPC Access connector to the function (gcloud functions deploy --vpc-connector=...).")
def function_vpc(function, index):
    skip = deleting(function)
    if skip:
        return skip
    config = get(function, "serviceConfig", dict)
    connector = optional(config, "vpcConnector", "", str)
    if connector:
        return result(False, vpc_connector=connector)
    direct = {k: v for k, v in config.items() if k.lower().startswith("directvpc") and v}
    if direct:
        return "MANUAL", {"reason": "Direct VPC egress is declared instead of a connector", "direct_vpc": sorted(direct)}
    environment = get(function, "environment", str)
    if environment == "GEN_2":
        service = backing_service(function, index)
        access = optional(optional(service, "template", {}, dict), "vpcAccess", None, dict)
        if access:
            return "MANUAL", {"reason": "VPC access is configured on the backing Cloud Run service, not the function",
                              "service": service["name"]}
    elif environment != "GEN_1":
        raise Unavailable("unrecognized function environment")
    return result(True, vpc_connector=None, environment=environment)


_VPC = {"environment": "GEN_2", "serviceConfig": {"service": _RUN}}
cases(track("function.vpc_connector_configured"),
      {"environment": "GEN_2", "serviceConfig": {"service": _RUN, "vpcConnector": "projects/p/locations/us-central1/connectors/c"}},
      _VPC, fail_index=scope_index({"cloudrun_service": [{"name": _RUN, "template": {}}]}),
      manual=_VPC, manual_index=scope_index({"cloudrun_service": [{"name": _RUN, "template": {
          "vpcAccess": {"networkInterfaces": [{"network": "default"}]}}}]}),
      unknown=_VPC, unknown_index={}, not_applicable={**_VPC, "state": "DELETING"},
      malformed={"environment": "GEN_1", "serviceConfig": {"vpcConnector": 7}})


# --- Cloud Run ---------------------------------------------------------------------------------------------

@gcp("cloudrun_service.invoker_not_public", "cloudrun_service", "Cloud Run service is not publicly invocable", severity="high",
     control="AC-3", category="exposure",
     remediation="Remove allUsers and allAuthenticatedUsers from roles/run.invoker and keep invoker IAM checks enabled "
                 "(invokerIamDisabled=false) unless the service is intentionally public.")
def run_public(service, index):
    status, evidence = run_exposure(service)
    if status == "MANUAL":
        return status, evidence
    return result(status == "FAIL", **evidence)


cases(track("cloudrun_service.invoker_not_public"), {"name": _RUN, "iamPolicy": _PRIVATE}, {"name": _RUN, "iamPolicy": _OPEN},
      manual={"name": _RUN, "iamPolicy": {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"],
                                                         "condition": {"expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}}]}},
      unknown={"name": _RUN, "iamPolicy": {"collection_status": "denied"}, "_coverage": {"iamPolicy": {"status": "denied"}}},
      malformed={"name": _RUN, "iamPolicy": {"bindings": [{"role": "roles/run.invoker", "members": "allUsers"}]}})


# --- API keys ------------------------------------------------------------------------------------------------

@gcp("api_key.created_within_90_days", "api_key", "API key was created within the last 90 days", control="IA-5",
     category="hardening", remediation="Create a replacement API key, move clients to it and delete keys older than 90 days.")
def api_key_age(key, index):
    if optional(key, "deleteTime", None, str):
        return "NOT_APPLICABLE", {"reason": "API key is deleted"}
    created = parse_time(get(key, "createTime", str))
    age = (captured_at(key, index) - created).days
    # Prowler semantics: FAIL when the elapsed whole days exceed 90.
    return result(age > 90, created=key["createTime"], age_days=age)


_AT = {"_provenance": {"collected_at": "2026-10-10T00:00:00Z"}}
cases(track("api_key.created_within_90_days"), {"createTime": "2026-07-12T00:00:00.123456789Z", **_AT},
      {"createTime": "2026-07-11T00:00:00Z", **_AT}, not_applicable={"createTime": "2020-01-01T00:00:00Z", "deleteTime": "2026-01-01T00:00:00Z"},
      malformed={"createTime": "yesterday", **_AT})


# --- BigQuery ------------------------------------------------------------------------------------------------

@gcp("bigquery_dataset.default_cmek", "bigquery_dataset", "BigQuery dataset declares a customer-managed default encryption key",
     severity="high", control="SC-12", category="hardening",
     remediation="Set defaultEncryptionConfiguration.kmsKeyName on the dataset (bq update --default_kms_key=...).")
def dataset_cmek(dataset, index):
    coverage = dataset.get("_coverage")
    details = coverage.get("datasetDetails") if isinstance(coverage, dict) else None
    if not isinstance(details, dict) or details.get("status") != "collected":
        raise Unavailable("dataset details (datasets.get) not collected")
    config = optional(dataset, "defaultEncryptionConfiguration", None, dict)
    key = optional(config, "kmsKeyName", "", str) if config is not None else ""
    return result(not key, kms_key_name=key or None)


_DETAILS = {"_coverage": {"datasetDetails": {"status": "collected"}}, "datasetReference": {"datasetId": "d"}}
cases(track("bigquery_dataset.default_cmek"),
      {**_DETAILS, "defaultEncryptionConfiguration": {"kmsKeyName": "projects/p/locations/us/keyRings/r/cryptoKeys/k"}},
      _DETAILS, unknown={"datasetReference": {"datasetId": "d"}, "_coverage": {"datasetDetails": {"status": "denied"}}},
      malformed={**_DETAILS, "defaultEncryptionConfiguration": {"kmsKeyName": 5}})


# --- Cloud SQL -----------------------------------------------------------------------------------------------

@gcp("sql_instance.only_private_ip_addresses", "sql_instance", "Cloud SQL instance has only PRIVATE IP address assignments",
     severity="high", control="SC-7", category="exposure",
     remediation="Disable public IPv4 (ipv4Enabled=false), remove outgoing public addresses and connect over private IP.")
def sql_private_only(instance, index):
    backend = optional(instance, "backendType", None, str)
    if backend == "EXTERNAL":
        return "NOT_APPLICABLE", {"reason": "External (on-premises) primary representation", "backend_type": backend}
    types = [get(row, "type", str) for row in list_of_objects(optional(instance, "ipAddresses", [], list))]
    if any(value not in ("PRIMARY", "PRIVATE", "OUTGOING", "MIGRATED_1ST_GEN") for value in types):
        raise Unavailable("unrecognized Cloud SQL IP address type")
    return result(any(t != "PRIVATE" for t in types), ip_address_types=types)


cases(track("sql_instance.only_private_ip_addresses"), {"backendType": "SECOND_GEN", "ipAddresses": [{"type": "PRIVATE"}]},
      {"backendType": "SECOND_GEN", "ipAddresses": [{"type": "PRIVATE"}, {"type": "OUTGOING"}]},
      not_applicable={"backendType": "EXTERNAL"}, malformed={"backendType": "SECOND_GEN", "ipAddresses": [{"type": None}]})
