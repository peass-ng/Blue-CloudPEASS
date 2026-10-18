"""Signed GCP configuration checks. All joins require complete scoped snapshot facts."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import re
from cryptography import x509

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects

# Exact digests of the ten-field entries in new-checks-gcp.json.
PROPOSED_SPEC_SHA256 = {
    "gcp_kms_key_destroy_alert": "23536ad706b18859e6756f3b3cc63816b444dfcd260143233607727c84f22609",
    "gcp_logging_enumeration_alert": "06fa0a5f22f10938f8c464bf242c4f19b83340a01740668067d98ed25dc280ed",
    "gcp_logging_query_rate_alert": "7c6b15c194e950d0a969d2903f9d2d595ef2880138636792ede359c892e81e5b",
    "gcp_c5_log_export": "55e999bd83e46eb1b1b4d0c2079c2f16a1497b7a114963cd6facba780f13b4fe",
    "gcp_c5_log_isolation": "b86a70176edb56f2925e8f15edb9c348c52176fecf08bafa76da3a5b0f7f3b83",
    "gcp_c5_logging_redundancy": "ed7d2440d422ac29cc30039d65ba3a2614469bf95b7c0f81e3042c643011c103",
    "gcp_c5_siem_sink": "65e3d163770298c4b2e4ce7cce45ea08371f5f2889f4a2e59f8ed3dbb7108cf8",
    "gcp_certificate_renewal_30_days": "6fa7627a63c7f8e02438aa30d6ee2e3acc4426cc717ef4de6943126006fbe0bd",
    "gcp_certificate_rotation_180_days": "7495d4bce8373e88ce246a2dbf70e5418ebe81762c53509c7475639624dd9126",
    "gcp_certificate_rotation_90_days": "cb9fe2ebb0c097908b5fea9dae9179c4909a856a91a36d66cdfe9ea3ef5fde6f",
    "gcp_c5_build_provenance": "87c24b21f4c4bb9640a6574fa17c7d38fc977a0e1810869b49a76ef8851113c2",
    "gcp_c5_cloudbuild_gate": "c2a9456ccb5442122913fb2b8881b35e170ffb80dd4fd290fad55be2265a9be4",
    "gcp_c5_workforce_federation": "35c0bfddbf151d9d1a2d5b6a769e3993afca15dcdd34f051dce32f9190d09f33",
    "gcp_iam_workforce_mfa": "47adf9c6c5e65059d7b299fd323ddd0500c75d97affa037e988ad6a5e523a371",
    "gcp_gke_small_cluster_auto_upgrade": "02a6a49152b3b74ae683f86a5c27d9a3b861e1f941d9b68ee73041056478d5ab",
}
IDS = tuple(PROPOSED_SPEC_SHA256)


def _scope(index, prefix):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "gcp":
        raise Unavailable("GCP provider authority unavailable")
    scope = get(context, "scope", str)
    suffix = scope[len(prefix):] if scope.startswith(prefix) else ""
    if not re.fullmatch(r"[A-Za-z0-9-]+", suffix):
        raise Unavailable("GCP scope unavailable")
    return scope


def _inventory(index, kind, prefix="projects/"):
    scope = _scope(index, prefix)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1 or not isinstance(envelopes[0], dict):
        raise Unavailable("scoped inventory unavailable: " + kind)
    envelope = envelopes[0]
    if envelope.get("type") != kind or envelope.get("scope") != scope:
        raise Unavailable("foreign inventory: " + kind)
    rows = complete_items(index, kind)
    declared = get(envelope, "items", list)
    wrappers = index.get(kind, [])
    if not isinstance(wrappers, list):
        raise Unavailable("malformed resource wrappers: " + kind)
    if (len(rows) != len(declared) or len(rows) != len(wrappers) or
            declared != rows or (envelope["status"] == "empty") != (not rows)):
        raise Unavailable("inconsistent inventory: " + kind)
    for row, native in zip(wrappers, rows):
        if get(row, "type", str) != kind or get(row, "scope", str) != scope or get(row, "data", dict) != native:
            raise Unavailable("foreign or inconsistent resource: " + kind)
    return rows


def _member(item, rows, name="name"):
    identity = get(item, name, str)
    if not identity or sum(get(row, name, str) == identity for row in rows) != 1 or item not in rows:
        raise Unavailable("resource absent or duplicate in complete inventory")
    return identity


def _policy(index, section, prefix="projects/"):
    scope = _scope(index, prefix)
    p = get(index, "context.metadata.compliance_policy", dict)
    if get(p, "status", str) != "collected" or get(p, "scope", str) != scope:
        raise Unavailable("approved policy unavailable or foreign scope")
    return get(p, section, dict)


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp unavailable")
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed timestamp") from exc
    if t.tzinfo is None:
        raise Unavailable("naive timestamp")
    return t.astimezone(timezone.utc)


def _now(index):
    return _instant(get(index, "context.created_at", str))


def _strings(obj, field):
    values = get(obj, field, list)
    if any(not isinstance(v, str) or not v for v in values) or len(values) != len(set(values)):
        raise Unavailable("malformed list: " + field)
    return values


def _sink_rows(item, index):
    rows = _inventory(index, "log_sink")
    scope = _scope(index, "projects/")
    if get(item, "provider", str) != "gcp" or get(item, "scope", str) != scope:
        raise Unavailable("foreign project scope context")
    names = []
    for row in rows:
        name = get(row, "name", str)
        if not name.startswith(scope + "/sinks/") or not name[len(scope)+7:]:
            raise Unavailable("foreign log sink")
        names.append(name)
    if len(names) != len(set(names)):
        raise Unavailable("duplicate log sink")
    return rows


def _sink_policy(index):
    p = _policy(index, "logging")
    # This explicit attestation is required because project sinks do not prove
    # that organization/folder aggregated sinks are absent.
    if get(p, "ancestor_inventory_complete", bool) is not True:
        raise Unavailable("ancestor sink inventory unavailable")
    ancestors = list_of_objects(get(p, "ancestor_sinks", list))
    for sink in ancestors:
        if not re.fullmatch(r"(?:organizations|folders)/[^/]+/sinks/[^/]+", get(sink, "name", str)):
            raise Unavailable("foreign ancestor sink")
        if get(sink, "includeChildren", bool) is not True:
            raise Unavailable("ancestor sink coverage uncertain")
    return p, ancestors


def _filter_covers(value, log_class):
    """Only prove an unfiltered sink or a simple equality/OR query."""
    if not isinstance(value, str):
        raise Unavailable("log filter unavailable")
    if value == "":
        return True
    terms = re.split(r"\s+OR\s+", value)
    found = []
    for term in terms:
        match = re.fullmatch(r'\s*protoPayload\.methodName\s*=\s*"([^"\s]+)"\s*', term)
        if not match:
            raise Unavailable("complex log filter cannot be proven")
        found.append(match.group(1))
    return log_class in found


def _sink_covers(row, log_class):
    disabled = get(row, "disabled", bool)
    destination = get(row, "destination", str)
    if not destination:
        raise Unavailable("sink destination unavailable")
    covered = _filter_covers(get(row, "filter", str), log_class)
    for exclusion in list_of_objects(get(row, "exclusions", list)):
        if get(exclusion, "disabled", bool) is False and _filter_covers(get(exclusion, "filter", str), log_class):
            covered = False
    return not disabled and covered


def _logging(item, index, mode):
    rows = _sink_rows(item, index)
    p, ancestors = _sink_policy(index)
    all_sinks = rows + ancestors
    if mode == "isolation":
        buckets = set(_strings(p, "customer_data_buckets"))
        exceptions = list_of_objects(get(p, "separation_exceptions", list))
        allowed = {(get(x, "sink", str), get(x, "bucket", str)) for x in exceptions}
        if get(p, "bucket_register_complete", bool) is not True:
            raise Unavailable("customer bucket register incomplete")
        unsafe = []
        external = False
        for sink in all_sinks:
            if get(sink, "disabled", bool):
                continue
            destination = get(sink, "destination", str)
            if destination.startswith("storage.googleapis.com/"):
                bucket = destination.removeprefix("storage.googleapis.com/")
                if not bucket or "/" in bucket:
                    raise Unavailable("malformed bucket sink destination")
                if bucket in buckets and (get(sink, "name", str), bucket) not in allowed:
                    unsafe.append(get(sink, "name", str))
            else:
                external = True
        if unsafe:
            return result(True, unsafe_sinks=sorted(unsafe))
        if external:
            return unknown("external sink destination separation unavailable")
        return result(False, sink_count=len(all_sinks))
    classes = _strings(p, "required_log_classes" if mode != "redundancy" else "critical_log_classes")
    if not classes:
        raise Unavailable("required log class contract empty")
    if mode == "redundancy" and get(p, "require_two_destinations", bool) is not True:
        return "NOT_APPLICABLE", {"reason": "approved architecture does not require two destinations"}
    destination = None
    if mode == "export":
        destination = get(p, "approved_customer_destination", str)
    if mode == "siem":
        destination = get(p, "approved_siem_destination", str)
    if destination == "":
        raise Unavailable("approved destination empty")
    lacking = []
    uncertain_independence = []
    independent = set()
    if mode == "redundancy":
        for pair in list_of_objects(get(p, "independent_destination_pairs", list)):
            values = _strings(pair, "destinations")
            if len(values) != 2 or values[0] == values[1]:
                raise Unavailable("malformed destination independence approval")
            independent.add(frozenset(values))
    for log_class in classes:
        candidates = [sink for sink in all_sinks if destination is None or get(sink, "destination", str) == destination]
        covered = {get(sink, "destination", str) for sink in candidates if _sink_covers(sink, log_class)}
        if len(covered) < (2 if mode == "redundancy" else 1):
            lacking.append(log_class)
        elif mode == "redundancy" and not any(pair <= covered for pair in independent):
            uncertain_independence.append(log_class)
    if lacking:
        return result(True, missing_classes=lacking, checked_classes=classes)
    if uncertain_independence:
        return unknown("destination independence unverified", log_classes=uncertain_independence)
    return result(False, missing_classes=[], checked_classes=classes)


def _cert(item, index, mode):
    rows = _inventory(index, "certificate")
    name = _member(item, rows)
    if not re.fullmatch(re.escape(_scope(index, "projects/")) + r"/locations/[^/]+/certificates/[^/]+", name):
        raise Unavailable("foreign certificate")
    now = _now(index)
    deployment = get(item, "deployment", dict)
    if get(deployment, "status", str) != "collected":
        raise Unavailable("certificate deployment association unavailable")
    deployed = get(deployment, "deployed", bool)
    if not deployed:
        return "NOT_APPLICABLE", {"certificate": name, "reason": "not deployed"}
    if mode == "renewal":
        expiry = _instant(get(item, "expireTime", str))
        domains = set(_strings(get(item, "managed", dict), "domains"))
        if not domains:
            raise Unavailable("certificate domains unavailable")
        if expiry - timedelta(days=30) > now:
            return result(False, certificate=name, threshold_crossed=False)
        replacements = list_of_objects(get(deployment, "replacements", list))
        threshold = expiry - timedelta(days=30)
        timely = False
        for candidate in replacements:
            if get(candidate, "name", str) == name:
                continue
            if get(candidate, "state", str) != "ACTIVE":
                continue
            covered = set(_strings(candidate, "domains"))
            activated = _instant(get(candidate, "deployedAt", str))
            if domains <= covered and activated <= min(now, threshold + timedelta(hours=24)):
                timely = True
        if get(deployment, "replacement_inventory_complete", bool) is not True:
            raise Unavailable("replacement inventory incomplete")
        if not timely and now < threshold + timedelta(hours=24):
            return unknown("24-hour replacement window remains open", certificate=name)
        return result(not timely, certificate=name, threshold_crossed=True)
    if mode == "180":
        state = get(item, "managed.state", str)
        if state != "ACTIVE":
            return "NOT_APPLICABLE", {"certificate": name, "reason": "not ACTIVE"}
        age = now - _instant(get(item, "createTime", str))
        if age < timedelta(0):
            raise Unavailable("future certificate creation")
        return result(age > timedelta(days=180), certificate=name, age_days=age.days)
    # Resource createTime is never an issuance timestamp.
    pem = get(item, "pemCertificate", str)
    if not pem.startswith("-----BEGIN CERTIFICATE-----"):
        raise Unavailable("leaf PEM unavailable")
    try:
        issued = x509.load_pem_x509_certificate(pem.encode("ascii")).not_valid_before_utc
    except (ValueError, UnicodeError) as exc:
        raise Unavailable("malformed leaf PEM") from exc
    age = now - issued
    if age < timedelta(0):
        raise Unavailable("future certificate issuance")
    return result(age > timedelta(days=90), certificate=name, age_days=age.days)


def _build(item, index, mode):
    rows = _inventory(index, "cloudbuild_trigger")
    name = _member(item, rows, "id")
    p = _policy(index, "cloudbuild")
    if get(p, "deployment_coverage", str) != "cloudbuild_only":
        raise Unavailable("deployments outside Cloud Build unresolved")
    if get(p, "production_trigger_scope_complete", bool) is not True:
        raise Unavailable("production trigger scope incomplete")
    ids = _strings(p, "production_trigger_ids")
    if name not in ids:
        return "NOT_APPLICABLE", {"trigger": name, "reason": "outside approved production scope"}
    if mode == "gate":
        required = get(p, "approval_required", bool)
        approval = get(item, "approvalConfig.approvalRequired", bool)
        step = get(p, "security_test_step", str)
        if not step:
            raise Unavailable("required security test undefined")
        definition = get(item, "buildDefinition", dict)
        if get(definition, "status", str) != "collected":
            raise Unavailable("file-backed build definition unreadable")
        steps = list_of_objects(get(definition, "steps", list))
        ids = [get(s, "id", str) for s in steps]
        return result((required and not approval) or step not in ids,
                      trigger=name, approval_required=required, security_test_step=step)
    builds = _inventory(index, "cloudbuild_build")
    matched = [b for b in builds if get(b, "triggerId", str) == name]
    build_ids = [get(b, "id", str) for b in builds]
    if len(build_ids) != len(set(build_ids)):
        raise Unavailable("duplicate Cloud Build build")
    if not matched:
        raise Unavailable("no production deployment build association")
    bad = []
    for build in matched:
        build_id = get(build, "id", str)
        if get(build, "productionDeployment", bool) is not True:
            continue
        status = get(build, "status", str)
        if status not in {"SUCCESS", "FAILURE", "CANCELLED", "TIMEOUT", "WORKING", "QUEUED", "EXPIRED", "INTERNAL_ERROR"}:
            raise Unavailable("unrecognized build status")
        provenance = get(build, "sourceProvenance.resolvedRepoSource.commitSha", str)
        substitution = get(build, "substitutions.COMMIT_SHA", str)
        if status != "SUCCESS" or not (provenance or substitution):
            bad.append(build_id)
    if not matched or not any(get(b, "productionDeployment", bool) for b in matched):
        raise Unavailable("production build association incomplete")
    return result(bool(bad), trigger=name, unsafe_builds=bad)


def _workforce(item, index, mode):
    rows = _inventory(index, "workforce_pool", "organizations/")
    name = _member(item, rows)
    scope = _scope(index, "organizations/")
    if not name.startswith("locations/global/workforcePools/"):
        raise Unavailable("foreign workforce pool")
    p = _policy(index, "workforce", "organizations/")
    if get(p, "mapping_complete", bool) is not True:
        raise Unavailable("customer provider mapping incomplete")
    mapping = list_of_objects(get(p, "customer_provider_mapping", list))
    applicable = [m for m in mapping if get(m, "pool", str) == name]
    if not applicable:
        return "NOT_APPLICABLE", {"pool": name, "reason": "outside approved customer mapping"}
    providers = _inventory(index, "workforce_provider", "organizations/")
    provider_ids = [get(v, "name", str) for v in providers]
    valid_pool_names = {get(pool, "name", str) for pool in rows}
    if (len(provider_ids) != len(set(provider_ids)) or
            any(not any(v.startswith(pool_name + "/providers/") and
                        v[len(pool_name)+11:] and "/" not in v[len(pool_name)+11:]
                        for pool_name in valid_pool_names) for v in provider_ids)):
        raise Unavailable("duplicate or foreign workforce provider")
    mapped_ids = [get(m, "provider", str) for m in applicable]
    if len(mapped_ids) != len(set(mapped_ids)):
        raise Unavailable("duplicate customer provider mapping")
    if mode == "federation" and get(item, "state", str) != "ACTIVE":
        return result(True, pool=name, reason="pool not ACTIVE")
    bad = []
    seen = []
    for contract in applicable:
        provider_name = get(contract, "provider", str)
        matches = [v for v in providers if get(v, "name", str) == provider_name]
        if len(matches) != 1 or not provider_name.startswith(name + "/providers/"):
            raise Unavailable("mapped workforce provider unavailable")
        provider = matches[0]
        seen.append(provider_name)
        if mode == "federation":
            issuer = get(contract, "issuer", str)
            audiences = set(_strings(contract, "audiences"))
            configured = set(_strings(get(provider, "oidc", dict), "allowedAudiences"))
            if not issuer or not audiences:
                raise Unavailable("approved issuer/audience contract empty")
            if get(provider, "state", str) != "ACTIVE" or get(provider, "oidc.issuerUri", str) != issuer or not configured or not configured <= audiences:
                bad.append(provider_name)
        else:
            if get(provider, "state", str) != "ACTIVE":
                continue
            claim = get(contract, "mfa_claim", str)
            expected = get(contract, "mfa_mapping", str)
            assurance = get(contract, "idp_assurance_verified", bool)
            if not claim or not expected or not assurance:
                raise Unavailable("IdP MFA assurance contract unavailable")
            attrs = get(provider, "attributeMapping", dict)
            if attrs.get(claim) != expected:
                bad.append(provider_name)
    return result(bool(bad), pool=name, checked_providers=seen, unsafe_providers=bad)


def _gke(item, index):
    rows = _inventory(index, "gke_cluster")
    name = _member(item, rows)
    if not re.fullmatch(re.escape(_scope(index, "projects/")) + r"/locations/[^/]+/clusters/[^/]+", name):
        raise Unavailable("foreign GKE cluster")
    pools = list_of_objects(get(item, "nodePools", list))
    if not pools:
        raise Unavailable("node pool inventory unavailable")
    managers = _inventory(index, "instance_group_manager")
    by_url = {get(m, "instanceGroup", str): m for m in managers}
    if len(by_url) != len(managers):
        raise Unavailable("duplicate instance group manager")
    project_path = "/projects/" + _scope(index, "projects/").removeprefix("projects/") + "/"
    if any(project_path not in url or "/instanceGroups/" not in url for url in by_url):
        raise Unavailable("foreign instance group")
    total = 0
    disabled = []
    for pool in pools:
        pool_name = get(pool, "name", str)
        urls = _strings(pool, "instanceGroupUrls")
        if not urls:
            raise Unavailable("node pool instance groups unavailable")
        auto = get(pool, "management.autoUpgrade", bool)
        if not auto:
            disabled.append(pool_name)
        for url in urls:
            if url not in by_url:
                raise Unavailable("instance group targetSize unavailable")
            size = get(by_url[url], "targetSize", int)
            if size < 0:
                raise Unavailable("negative instance group targetSize")
            total += size
    return result(total < 3 and bool(disabled), cluster=name, target_nodes=total,
                  pools_without_auto_upgrade=disabled)


def _alerts(item, index, mode):
    scope = _scope(index, "projects/")
    if get(item, "provider", str) != "gcp" or get(item, "scope", str) != scope:
        raise Unavailable("foreign project scope context")
    metrics = _inventory(index, "logging_metric")
    policies = _inventory(index, "alert_policy")
    if mode == "query":
        p = _policy(index, "monitoring")
        approved = get(p, "approved_query_count", int)
        if approved < 1:
            raise Unavailable("invalid approved query count")
    metric_names = [get(metric, "name", str) for metric in metrics]
    policy_names = [get(policy, "name", str) for policy in policies]
    if len(metric_names) != len(set(metric_names)) or len(policy_names) != len(set(policy_names)):
        raise Unavailable("duplicate metric or alert identity")
    for metric in metrics:
        metric_name = get(metric, "name", str)
        prefix = scope + "/metrics/"
        if not metric_name.startswith(prefix) or not metric_name[len(prefix):] or "/" in metric_name[len(prefix):]:
            raise Unavailable("metric identity unavailable or foreign")
        metric_id = metric_name[len(prefix):]
        if "metricId" in metric and get(metric, "metricId", str) != metric_id:
            raise Unavailable("metric ID conflicts with native name")
        if "disabled" in metric and get(metric, "disabled", bool):
            continue
        flt = get(metric, "filter", str)
        if mode == "kms":
            clauses = re.split(r"\s+OR\s+", flt)
            names = []
            for clause in clauses:
                match = re.fullmatch(r'protoPayload\.methodName\s*=\s*"([^"\s]+)"', clause.strip())
                if not match:
                    raise Unavailable("KMS metric filter semantics unrecognized")
                names.append(match.group(1))
            disable = {"DisableCryptoKeyVersion", "google.cloud.kms.v1.KeyManagementService.DisableCryptoKeyVersion"}
            destroy = {"DestroyCryptoKeyVersion", "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion"}
            target = any(x in disable for x in names) and any(x in destroy for x in names)
        elif mode == "enumeration":
            if flt != 'protoPayload.methodName =~ "\\.(list|get)$"':
                raise Unavailable("enumeration metric filter semantics unrecognized")
            target = True
        else:
            if flt != 'protoPayload.methodName="logging.entries.list"':
                raise Unavailable("query metric filter semantics unrecognized")
            target = True
        if mode != "kms" and target:
            extractors = get(metric, "labelExtractors", dict)
            principal_labels = {key for key, value in extractors.items()
                if value == "EXTRACT(protoPayload.authenticationInfo.principalEmail)"}
            target = bool(principal_labels)
        if not target:
            continue
        for policy in policies:
            if not get(policy, "enabled", bool):
                continue
            channels = _strings(policy, "notificationChannels")
            if mode != "kms" and not channels:
                continue
            for condition in list_of_objects(get(policy, "conditions", list)):
                threshold = get(condition, "conditionThreshold", dict)
                series = get(threshold, "filter", str)
                if series != f'metric.type="logging.googleapis.com/user/{metric_id}"':
                    continue
                if mode == "kms":
                    return result(False, metric=metric_name, alert=get(policy, "name", str))
                if get(threshold, "comparison", str) != "COMPARISON_GT":
                    continue
                limit = get(threshold, "thresholdValue", (int, float))
                if limit < 0 or limit > (approved if mode == "query" else 10):
                    continue
                aggs = list_of_objects(get(threshold, "aggregations", list))
                if any(get(a, "alignmentPeriod", str) == "300s" and
                       get(a, "perSeriesAligner", str) in ("ALIGN_SUM", "ALIGN_COUNT") and
                       any(s in {"metric.label." + label for label in principal_labels}
                           for s in _strings(a, "groupByFields"))
                       for a in aggs):
                    return result(False, metric=metric_name, alert=get(policy, "name", str))
    return result(True, project=scope, reason="no qualifying enabled alert in complete inventories")


# register currently validates an older category vocabulary. Register with its
# accepted category, then replace immutable metadata with the signed category.
def _signed(id, category, kind, title, severity, remediation, deps, target="resource"):
    def decorate(fn):
        registered = register(id, "gcp", "hardening", kind, title, severity, "CM-6", remediation,
                              dependencies=deps, target=target)(fn)
        CHECKS[-1] = replace(CHECKS[-1], category=category)
        return registered
    return decorate


@_signed("gcp_kms_key_destroy_alert", "monitoring", "project", "KMS key disable or destroy events lack an alert", "high", "Create an enabled alert on log metrics matching Cloud KMS key-version disable and destroy API method names.", ["logging_metric", "alert_policy"], "scope")
def kms_key_destroy_alert(item, index): return _alerts(item, index, "kms")

@_signed("gcp_logging_enumeration_alert", "monitoring", "project", "Cloud resource enumeration lacks an alert", "medium", "Create a log metric filtering .list/.get audit methods by principal and an enabled five-minute alert at ten events with a channel.", ["logging_metric", "alert_policy"], "scope")
def logging_enumeration_alert(item, index): return _alerts(item, index, "enumeration")

@_signed("gcp_logging_query_rate_alert", "monitoring", "project", "Excessive log queries lack an alert", "medium", "Create a log metric for logging.entries.list by principal and an enabled 300-second threshold alert using approved_query_count.", ["logging_metric", "alert_policy"], "scope")
def logging_query_rate_alert(item, index): return _alerts(item, index, "query")

@_signed("gcp_c5_log_export", "logging", "log_sink", "Customer audit log export availability", "medium", "Create an enabled Cloud Logging sink to the approved customer-access destination with filters covering required audit classes.", ["log_sink"], "scope")
def c5_log_export(item, index): return _logging(item, index, "export")

@_signed("gcp_c5_log_isolation", "logging", "log_sink", "Log and customer-data storage isolation", "medium", "Change the sink destination to a dedicated log bucket outside the customer-data bucket register, or record the approved exception.", ["log_sink"], "scope")
def c5_log_isolation(item, index): return _logging(item, index, "isolation")

@_signed("gcp_c5_logging_redundancy", "availability", "log_sink", "Critical log destination redundancy", "medium", "Create a second enabled sink to an independent approved destination for each critical log class.", ["log_sink"], "scope")
def c5_logging_redundancy(item, index): return _logging(item, index, "redundancy")

@_signed("gcp_c5_siem_sink", "logging", "log_sink", "Audit log export to approved SIEM", "medium", "Create an enabled project or organization sink for required audit classes to the approved SIEM destination; remove exclusions.", ["log_sink"], "scope")
def c5_siem_sink(item, index): return _logging(item, index, "siem")

@_signed("gcp_certificate_renewal_30_days", "encryption", "certificate", "Certificate lacks timely renewal", "high", "Deploy an ACTIVE replacement Certificate Manager certificate for the same domains at least 30 days before expiry.", ["certificate"])
def certificate_renewal(item, index): return _cert(item, index, "renewal")

@_signed("gcp_certificate_rotation_180_days", "encryption", "certificate", "Deployed certificate exceeds 180-day rotation limit", "high", "Replace deployed certificates before their createTime exceeds 180 days and update the certificate map entry.", ["certificate"])
def certificate_rotation_180(item, index): return _cert(item, index, "180")

@_signed("gcp_certificate_rotation_90_days", "encryption", "certificate", "Deployed certificate exceeds 90-day rotation limit", "high", "Replace deployed certificates before their leaf issuance age exceeds 90 days and update the certificate map entry.", ["certificate"])
def certificate_rotation_90(item, index): return _cert(item, index, "90")

@_signed("gcp_c5_build_provenance", "secure_development", "cloudbuild_trigger", "Production build source revision trace", "medium", "Make production Cloud Build builds retain sourceProvenance.resolvedRepoSource.commitSha and deploy only successful recorded builds.", ["cloudbuild_trigger", "cloudbuild_build"])
def c5_build_provenance(item, index): return _build(item, index, "provenance")

@_signed("gcp_c5_cloudbuild_gate", "secure_development", "cloudbuild_trigger", "Production build security gate", "medium", "Enable approvalConfig.approvalRequired and add the required security-test build step to each production Cloud Build trigger.", ["cloudbuild_trigger"])
def c5_cloudbuild_gate(item, index): return _build(item, index, "gate")

@_signed("gcp_c5_workforce_federation", "identity", "workforce_pool", "Customer identity federation configuration", "medium", "Enable the approved workforce pool and provider, and set oidc.issuerUri and allowedAudiences to the customer mapping.", ["workforce_pool", "workforce_provider"])
def c5_workforce_federation(item, index): return _workforce(item, index, "federation")

@_signed("gcp_iam_workforce_mfa", "identity", "workforce_pool", "Workforce federation lacks MFA assurance", "high", "Map and require a verified MFA assurance claim in each enabled workforce provider's attributeMapping/IdP policy.", ["workforce_pool", "workforce_provider"])
def iam_workforce_mfa(item, index): return _workforce(item, index, "mfa")

@_signed("gcp_gke_small_cluster_auto_upgrade", "vulnerability", "gke_cluster", "Small GKE cluster lacks node auto upgrade", "medium", "Enable nodePools[].management.autoUpgrade on every node pool in clusters with fewer than three target nodes.", ["gke_cluster", "instance_group_manager"])
def gke_small_cluster_auto_upgrade(item, index): return _gke(item, index)
