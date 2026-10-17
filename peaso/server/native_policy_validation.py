"""Intake bounds for explicit operator review inputs used by native batches.

These declarations select scope and approved behavior. They do not supply cloud
observations, credential identity, API endpoints, or evidence provenance.
"""
import json
import math
import re


def bounded(value):
    if not isinstance(value, dict) or not value or len(json.dumps(value, allow_nan=False)) > 50000:
        raise ValueError("review policy must be a bounded nonempty object")
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > 14 or count > 8192:
            raise ValueError("review policy nesting exceeds bounds")
        if isinstance(item, dict):
            if len(item) > 256 or any(not isinstance(k, str) or not 0 < len(k) <= 256 for k in item):
                raise ValueError("invalid review map")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if len(item) > 256:
                raise ValueError("review list exceeds bounds")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > 8192 or any(ord(c) < 32 and c not in "\r\n\t" for c in item):
                raise ValueError("invalid review text")
        elif item is not None and (type(item) not in (int, float, bool) or not math.isfinite(item)):
            raise ValueError("invalid review value")


def _scoped(value, fields, scope_pattern):
    bounded(value)
    if set(value) - fields or value.get("status") != "collected" or not re.fullmatch(scope_pattern, str(value.get("scope", ""))):
        raise ValueError("unsupported or unscoped review policy")


def organizations(value):
    bounded(value)
    if "by_scope" in value:
        if set(value) != {"by_scope"} or not isinstance(value["by_scope"], dict) or not value["by_scope"]:
            raise ValueError("invalid Organizations scope map")
        for scope, review in value["by_scope"].items():
            organizations(review)
            if "by_scope" in review or review["scope"] != scope:
                raise ValueError("Organizations scope identity differs")
        return
    fields = {"status", "scope", "audited_account_ids", "allowed_instance_types", "approved_break_glass_principals"}
    _scoped(value, fields, r"[0-9]{12}/global")
    for key in fields - {"status", "scope"}:
        if key in value:
            rows = value[key]
            if not isinstance(rows, list) or not rows or any(not isinstance(row, str) or not row for row in rows) or len(set(rows)) != len(rows):
                raise ValueError("invalid Organizations approved value list")
    if any(not re.fullmatch(r"[0-9]{12}", account) for account in value.get("audited_account_ids", [])):
        raise ValueError("invalid Organizations audited account")


def azure_sw31_review(review):
    """SW31 requirements only; never captured cloud or operational evidence."""
    bounded(review)
    regional = {"approvedRegions", "globalResourceTypes", "approvedZones"}
    lists = {"requiredCategories", "approvedSinkIds", "selectedResourceTypes", "requiredTagKeys",
             "inScopeResourceTypes", "requiredBackupItemIds"}
    thresholds = {"minRetentionDays", "backupWindowDays", "ops06MaxAgeDays"}
    allowed = regional | lists | thresholds | {"status", "scope", "requiredBackupItems", "approvedInternetPorts"}
    if set(review) - allowed:
        raise ValueError("unsupported SW31 requirements")
    if "status" in review and review["status"] != "collected":
        raise ValueError("regional approval unavailable")
    if "scope" in review and (not isinstance(review["scope"], str) or not re.fullmatch(r"/subscriptions/[A-Za-z0-9._-]{1,128}", review["scope"])):
        raise ValueError("regional approval scope invalid")
    for name in lists & set(review):
        values = review[name]
        if (not isinstance(values, list) or not values or
                any(not isinstance(v, str) or not v or v.strip() != v or any(ord(c) < 32 for c in v) for v in values) or
                len(set(values)) != len(values)):
            raise ValueError("invalid SW31 normative list")
    for name in thresholds & set(review):
        if type(review[name]) is not int or not 0 < review[name] <= 146000:
            raise ValueError("invalid SW31 normative threshold")
    if "approvedInternetPorts" in review:
        ports = review["approvedInternetPorts"]
        if (not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports) or
                len(set(ports)) != len(ports)):
            raise ValueError("invalid SW31 approved ports")
    if "requiredBackupItems" in review:
        items = review["requiredBackupItems"]
        if not isinstance(items, list) or not items:
            raise ValueError("invalid SW31 backup classifications")
        seen = set()
        for item in items:
            if (not isinstance(item, dict) or set(item) != {"id", "dataClass", "workloadType"} or
                    any(not isinstance(v, str) or not v or v.strip() != v or any(ord(c) < 32 for c in v) for v in item.values()) or
                    not item['id'].startswith('/subscriptions/') or item['id'].casefold() in seen):
                raise ValueError("invalid SW31 classified backup item")
            seen.add(item['id'].casefold())
    if not regional.intersection(review):
        return
    if regional - set(review):
        raise ValueError("incomplete regional requirements")
    regions = review["approvedRegions"]
    if (not isinstance(regions, list) or not regions or
            any(not isinstance(r, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,62}", r) for r in regions) or
            len({r.casefold() for r in regions}) != len(regions)):
        raise ValueError("approved regions invalid")
    resource_type = r"[A-Za-z][A-Za-z0-9.-]*/[A-Za-z][A-Za-z0-9]*(?:/[A-Za-z][A-Za-z0-9]*)*"
    exemptions = review["globalResourceTypes"]
    if (not isinstance(exemptions, list) or
            any(not isinstance(t, str) or not re.fullmatch(resource_type, t) for t in exemptions) or
            len({t.casefold() for t in exemptions}) != len(exemptions)):
        raise ValueError("regional type exemptions invalid")
    zones = review["approvedZones"]
    if (not isinstance(zones, dict) or
            any(not isinstance(t, str) or not re.fullmatch(resource_type, t) for t in zones) or
            len({t.casefold() for t in zones}) != len(zones)):
        raise ValueError("approved zone resource types invalid")
    for values in zones.values():
        if (not isinstance(values, list) or
                any(not isinstance(z, str) or not re.fullmatch(r"[1-9][0-9]{0,2}", z) for z in values) or
                len(set(values)) != len(values)):
            raise ValueError("approved zones invalid")


def azure_incident_triage_review(review):
    """Approved procedure criteria only; no incident observations or history flags."""
    _scoped(review, {'status', 'scope', 'incidentTriage'},
            r'/subscriptions/[A-Za-z0-9._-]{1,128}')
    if set(review) != {'status', 'scope', 'incidentTriage'}:
        raise ValueError('incident triage approval requires scope and procedure')
    criteria = review['incidentTriage']
    if not isinstance(criteria, dict) or set(criteria) != {
            'approvedTriageHours', 'observationWindowHours', 'requiredResponseSteps'}:
        raise ValueError('unsupported incident triage criteria')
    for field in ('approvedTriageHours', 'observationWindowHours'):
        if type(criteria[field]) is not int or not 0 < criteria[field] <= 2 ** 31 - 1:
            raise ValueError('invalid incident triage time threshold')
    steps = criteria['requiredResponseSteps']
    if (not isinstance(steps, list) or not steps
            or any(not isinstance(step, str) or not 0 < len(step) <= 256
                   or step != step.strip() or any(ord(c) < 32 or ord(c) == 127 for c in step)
                   for step in steps) or len(set(steps)) != len(steps)):
        raise ValueError('invalid incident response procedure steps')


def azure_detection(policy):
    bounded(policy)
    namespaces = {"azure_attack_detection", "sw12", "sw13", "sw15", "sw18", "sw16", "sw19", "sw21", "sw23", "sw24", "sw25", "sw26", "sw27", "sw31", "sw32", "sw33"}
    if set(policy) - namespaces - {"status", "scope", "checks"}:
        raise ValueError("unsupported Azure detection policy")
    if set(policy) & {"status", "scope", "checks"}:
        flat = {key: policy[key] for key in ("status", "scope", "checks") if key in policy}
        _scoped(flat, {"status", "scope", "checks"}, r"/subscriptions/[A-Za-z0-9._-]{1,128}")
        _check_review_map(flat.get("checks"), "compliance_new_sw17")
        updates = flat['checks'].get('azure.gap.compute_vm_system_updates_installed', {})
        for flag in ('requireActualInstallation', 'requirePciCompliance'):
            if flag in updates and type(updates[flag]) is not bool:
                raise ValueError('invalid native VM patch requirement')
    for name, review in policy.items():
        if name not in namespaces:
            continue
        if name == "sw27":
            azure_incident_triage_review(review)
            continue
        if name == "sw31":
            azure_sw31_review(review)
            continue
        if name == "sw13":
            from peaso.collectors.azure_security_correlation_native import KEY, normalize
            if isinstance(review, dict) and isinstance(review.get('checks'), dict) and KEY in review['checks']:
                normalize(review)
            else:
                azure_mfa_review(review)
            continue
        if name == "sw18":
            azure_guest_baselines(review)
            continue
        if name == "sw15":
            from peaso.collectors.azure_sw15_policy import normalize
            normalize({"compliance_policy": {"sw15": review}})
            continue
        if name == "sw32":
            from peaso.azure_sw32_policy import normalize_sw32
            normalize_sw32(review)
            continue
        if name == "sw23":
            azure_apim_protocol_review(review)
            continue
        if name == "sw24":
            azure_apim_review(review)
            continue
        if name == "sw25":
            azure_guest_review_policy(review)
            continue
        if name in {"sw16", "sw19", "sw26"}:
            module = "compliance_new_" + name
            if name == "sw16":
                _check_review_map(review, module, individually_scoped=True)
            else:
                _scoped(review, set(review), r"/subscriptions/[A-Za-z0-9._-]{1,128}")
                _check_review_map({key: value for key, value in review.items() if key not in {"status", "scope"}}, module)
            continue
        if name == "sw33":
            from peaso.collectors.azure_databricks_native import normalize as databricks_policy
            databricks_policy({"compliance_policy": {"sw33": review}})
            fields = {"status", "scope", "routeDestinations", "azureFilesKeys", "vpnTunnels", "classification",
                      "certificateIssuance", "databricksAccount", "backupAlerts", "messagingCmk", "changeApproval"}
            _scoped(review, fields, r"/subscriptions/[A-Za-z0-9._-]{1,128}")
            continue
        if name == "sw21":
            _scoped(review, {"status", "scope", "entraDiagnostics", "purview", "databox", "firewallDiagnostics", "loadBalancerChanges", "passwords"},
                    r"/(?:subscriptions/[A-Za-z0-9._-]{1,128}|tenants/[0-9a-fA-F-]{36})")
            continue
        scope_key = "subscription_scope" if name == "azure_attack_detection" else "scope"
        if not isinstance(review, dict) or set(review) - {"status", scope_key, "checks", "observed_at", "max_age_seconds"}:
            raise ValueError("invalid Azure detection review")
        if review.get("status") != "collected" or not re.fullmatch(r"/subscriptions/[A-Za-z0-9._-]{1,128}", str(review.get(scope_key, ""))):
            raise ValueError("unscoped Azure detection review")
        checks = review.get("checks")
        if not isinstance(checks, dict) or not checks or len(checks) > 64 or any(
                not re.fullmatch(r"azure\.other\.(?:attack_t[0-9]{4}|enumeration_alert)", cid) or not isinstance(check, dict)
                for cid, check in checks.items()):
            raise ValueError("invalid Azure check review")


def azure_guest_review_policy(value):
    """Normative guest review and alert criteria; no observed test outcomes."""
    _scoped(value, {"status", "scope", "checks"},
            r"/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
    monthly = "azure.cis.guest_users_reviewed_monthly_basis"
    regular = "azure.cis.guest_users_reviewed_regular_basis"
    gateway = "azure.other.gateway_backend_health_alert"
    routing = "azure_pci_10_2_1_1_8"
    metric_settings = "azure_diagnostic_setting_11_5_2_3_7959930"
    required_metrics = "azure_storage_account_monitor_alert_create_update_sqlserver_fr_7a7ddfa"
    checks = value.get("checks")
    if not isinstance(checks, dict) or not checks or set(checks) - {monthly, regular, gateway, routing, metric_settings, required_metrics}:
        raise ValueError("unsupported native guest review check")
    for cid, review in checks.items():
        if cid in (metric_settings, required_metrics):
            from peaso.checks.compliance_new_sw25_facts import _arm, _strings, _text, ARM_TYPES
            field = 'expectedMetricSettings' if cid == metric_settings else 'requiredMetrics'
            if not isinstance(review, dict) or set(review) != {field}:
                raise ValueError('unsupported metric requirements')
            requirements = review[field]
            if (not isinstance(requirements, list) or len(requirements) > 1000
                    or any(not isinstance(entry, dict) for entry in requirements)
                    or (cid == metric_settings and not requirements)):
                raise ValueError('invalid metric requirements inventory')
            for entry in requirements:
                if cid == required_metrics:
                    if set(entry) - {'resourceId', 'metricName', 'metricNamespace'}:
                        raise ValueError('unsupported required metric fields')
                    _arm(entry.get('resourceId'), value['scope'])
                    _text(entry.get('metricName'))
                    if entry.get('metricNamespace') is not None:
                        _text(entry['metricNamespace'])
                    continue
                if set(entry) - {'scopes', 'severity', 'evaluationFrequency', 'windowSize', 'criteria', 'actionGroupIds'}:
                    raise ValueError('unsupported expected metric fields')
                criteria = entry.get('criteria')
                if not isinstance(criteria, dict) or set(criteria) != {'odata.type', 'allOf'}:
                    raise ValueError('unsupported expected metric criteria')
                conditions = criteria['allOf']
                if not isinstance(conditions, list) or len(conditions) > 100:
                    raise ValueError('invalid metric conditions')
                for condition in conditions:
                    if (not isinstance(condition, dict) or set(condition) != {'criterionType', 'metricName', 'metricNamespace', 'timeAggregation', 'operator', 'threshold', 'dimensions'}):
                        raise ValueError('unsupported expected metric condition')
                    dimensions = condition['dimensions']
                    if (not isinstance(dimensions, list) or len(dimensions) > 100
                            or any(not isinstance(d, dict) or set(d) != {'name', 'operator', 'values'} for d in dimensions)):
                        raise ValueError('unsupported metric dimensions')
                from peaso.checks.compliance_new_sw25_monitoring import _setting
                _setting(entry, value['scope'], expected=True)
                groups = entry.get('actionGroupIds')
                if groups is not None:
                    if not groups: raise ValueError('explicit expected action groups empty')
                    for group in _strings(groups):
                        _arm(group, value['scope'], ARM_TYPES['action_group'])
            continue
        if cid == routing:
            if not isinstance(review, dict) or set(review) - {'actionGroupId'}:
                raise ValueError('unsupported alert routing requirements')
            group = review.get('actionGroupId')
            if group is not None and (not isinstance(group, str) or len(group) > 2048
                    or not re.fullmatch(re.escape(value['scope']) + r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft.Insights/actionGroups/[^/?#%\\\s]+', group, re.I)
                    or any(part in ('.', '..') for part in group.split('/'))
                    or any(ord(c) < 32 or ord(c) == 127 for c in group)):
                raise ValueError('invalid required alert action group')
            continue
        if cid == gateway:
            from datetime import datetime
            fields = {'windowStart', 'windowEnd', 'maxAlertLatencySeconds',
                      'evaluationIntervalSeconds', 'targetDenominator'}
            if not isinstance(review, dict) or set(review) != fields or review['targetDenominator'] != 'totalTargetsAtWindowStart':
                raise ValueError('unsupported gateway alert requirements')
            for name in ('maxAlertLatencySeconds', 'evaluationIntervalSeconds'):
                if type(review[name]) is not int or not 0 < review[name] <= 86400:
                    raise ValueError('invalid gateway monitoring interval')
            instants = []
            for name in ('windowStart', 'windowEnd'):
                if not isinstance(review[name], str) or len(review[name]) > 64:
                    raise ValueError('invalid gateway monitoring window')
                instant = datetime.fromisoformat(review[name].replace('Z', '+00:00'))
                if instant.utcoffset() is None:
                    raise ValueError('gateway monitoring window needs timezone')
                instants.append(instant)
            if instants[0] >= instants[1]:
                raise ValueError('gateway monitoring window inverted')
            continue
        fields = {"maxReviewAgeDays"} if cid == regular else set()
        if not isinstance(review, dict) or set(review) != fields:
            raise ValueError("unsupported guest review requirement")
        if cid == regular and (type(review["maxReviewAgeDays"]) is not int or
                               not 1 <= review["maxReviewAgeDays"] <= 3660):
            raise ValueError("guest review age must be an approved positive day count")


def _check_review_map(value, module, *, individually_scoped=False):
    bounded(value)
    from peaso.checks.bulk_pending import MANIFEST
    allowed = {cid for cid, contract in MANIFEST["checks"].items() if contract["source_module"] == module}
    if set(value) - allowed or any(not isinstance(entry, dict) for entry in value.values()):
        raise ValueError("unsupported native check review identity")
    if individually_scoped:
        for review in value.values():
            _scoped(review, set(review), r"/(?:subscriptions/[A-Za-z0-9._-]{1,128}|tenants/[0-9a-fA-F-]{36})")


def gcp_review(name, value):
    common = {"status", "scope", "observed_at", "max_age_seconds"}
    fields = common | ({"approved_asset_types", "audit_window"} if name == "sw51_policy" else
                       {"approved_on_call_topics", "consent_scopes", "log_coverage"})
    scope = r"projects/[a-z][a-z0-9-]{3,62}" if name == "sw51_policy" else r"(?:projects/[a-z][a-z0-9-]{3,62}|organizations/[0-9]{1,32})"
    _scoped(value, fields, scope)


def aws_transport(value):
    bounded(value)
    if "by_scope" in value:
        if set(value) != {"by_scope"} or not isinstance(value["by_scope"], dict) or not value["by_scope"]:
            raise ValueError("invalid TLS review scope map")
        for scope, review in value["by_scope"].items():
            aws_transport(review)
            if "by_scope" in review or review["scope"] != scope:
                raise ValueError("TLS review scope identity differs")
        return
    _scoped(value, {"status", "scope", "approved_tls_policies"}, r"[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z]+)+-[0-9]+)")
    names = value.get("approved_tls_policies")
    if not isinstance(names, list) or not names or any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
        raise ValueError("invalid approved TLS policy list")


def gcp_backup(value):
    fields = {"status", "scope", "sql_scope", "approved_offsite_policy"}
    _scoped(value, fields, r"projects/[a-z][a-z0-9-]{3,62}")
    if "approved_offsite_policy" in value and not isinstance(value["approved_offsite_policy"], bool):
        raise ValueError("backup approval must be a boolean")
    if "sql_scope" in value and (not isinstance(value["sql_scope"], list) or
            any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name) for name in value["sql_scope"])):
        raise ValueError("invalid approved SQL scope")


"""Scoped operator MFA requirements, never observations about enforcement."""
def azure_mfa_review(value):
    from datetime import datetime
    import re
    from peaso.server.native_policy_validation import bounded, _scoped
    fields = {'status', 'scope', 'authorized_by', 'document_id', 'observed_at', 'expires_at', 'checks'}
    _scoped(value, fields, r'/tenants/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')
    for name in ('authorized_by', 'document_id'):
        if not isinstance(value.get(name), str) or not value[name].strip():
            raise ValueError('MFA review owner and document are required')
    dates = []
    for name in ('observed_at', 'expires_at'):
        try:
            date = datetime.fromisoformat(value[name].replace('Z', '+00:00'))
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise ValueError('MFA review dates are required') from error
        if date.utcoffset() is None:
            raise ValueError('MFA review dates need a timezone')
        dates.append(date)
    if dates[0] >= dates[1]:
        raise ValueError('MFA review expiry must follow approval')
    prefix = 'azure|cis|'
    allowed = {prefix + name for name in ('multifactor_authentication_policy_exists_administrative_groups',
        'multifactor_authentication_policy_exists_users', 'multifactor_authentication_risky_sign_ins')}
    from peaso.collectors.azure_ca_consideration_native import KEY as device_key, validate_config as validate_device_config
    from peaso.collectors.azure_geo_consideration_native import KEY as geo_key, validate_config as validate_geo_config
    allowed.update((device_key, geo_key))
    checks = value.get('checks')
    if not isinstance(checks, dict) or not checks or set(checks) - allowed:
        raise ValueError('unsupported MFA review check')
    list_fields = {'requiredApplications', 'requiredClientAppTypes', 'designatedUsers', 'designatedGroups', 'designatedRoles'}
    for cid, review in checks.items():
        if cid == device_key:
            validate_device_config(review)
            continue
        if cid == geo_key:
            validate_geo_config(review)
            continue
        if not isinstance(review, dict) or set(review) - list_fields - {'userScope', 'riskLicensingConfirmed'}:
            raise ValueError('unsupported MFA review field')
        if review.get('userScope') not in ('all', 'designated', 'administrative'):
            raise ValueError('unsupported MFA review user scope')
        for name in list_fields:
            if name not in review:
                if name in ('requiredApplications', 'requiredClientAppTypes'):
                    raise ValueError('MFA review application and client coverage is required')
                continue
            rows = review[name]
            if (not isinstance(rows, list) or (name.startswith('required') and not rows)
                    or any(not isinstance(row, str) or not row.strip() for row in rows) or len(set(rows)) != len(rows)):
                raise ValueError('invalid MFA review identity list')
        if 'riskLicensingConfirmed' in review and type(review['riskLicensingConfirmed']) is not bool:
            raise ValueError('MFA licensing confirmation must be boolean')


"""Approved guest baselines select native report subjects, never report facts."""
def azure_guest_baselines(value):
    from peaso.server.native_policy_validation import _scoped
    _scoped(value, {'status', 'scope', 'userRightsBaseline', 'timeSyncBaseline', 'approvedTimeSourceIds'},
            r'/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')
    if not set(value) & {'userRightsBaseline', 'timeSyncBaseline'}:
        raise ValueError('at least one approved guest baseline is required')
    for name in ('userRightsBaseline', 'timeSyncBaseline'):
        if name not in value:
            continue
        baseline = value[name]
        fields = {'name', 'version', 'parameters', 'maxAgeSeconds'}
        if name == 'timeSyncBaseline':
            fields |= {'measurementResourceId', 'measurementReasonCode'}
        if not isinstance(baseline, dict) or set(baseline) != fields:
            raise ValueError('guest baseline must name an exact version and parameters')
        for field in fields - {'parameters', 'maxAgeSeconds'}:
            if not isinstance(baseline[field], str) or not baseline[field].strip():
                raise ValueError('guest baseline identity is required')
        if type(baseline['maxAgeSeconds']) is not int or not 1 <= baseline['maxAgeSeconds'] <= 31 * 86400:
            raise ValueError('guest baseline freshness is outside supported bounds')
        parameters = baseline['parameters']
        if not isinstance(parameters, dict) or any(not key or not isinstance(value, str) for key, value in parameters.items()):
            raise ValueError('guest baseline parameters must contain exact string values')
    if 'timeSyncBaseline' in value or 'approvedTimeSourceIds' in value:
        sources = value.get('approvedTimeSourceIds')
        if (not isinstance(sources, list) or not sources or any(not isinstance(s, str) or not s.strip() for s in sources)
                or len(set(sources)) != len(sources)):
            raise ValueError('approved time sources must be a nonempty unique list')


def azure_apim_review(value):
    from datetime import datetime, timezone, timedelta
    import math,re
    _scoped(value, {'status','scope','checks'}, r'/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}')
    prefix='azure_api_management_app_http_logs_enabled_'
    http,verbose,methods=(prefix+x for x in ('21c108d','9b3b56e','9ef06db'))
    checks=value.get('checks')
    if not isinstance(checks,list) or not checks or len(checks)>64:
        raise ValueError('APIM review needs explicit check requirements')
    seen=set()
    for review in checks:
        if not isinstance(review,dict):raise ValueError('APIM check review must be an object')
        cid=review.get('check_id');service=review.get('resource_id')
        extra={'minimumSamplingPercentage','window'} if cid==http else {'requiredApiIds','window'} if cid==verbose else {'window'} if cid==methods else None
        if extra is None or set(review)-{'status','check_id','resource_id'}-extra or review.get('status')!='collected':
            raise ValueError('unsupported APIM check review')
        if not isinstance(service,str) or not re.fullmatch(re.escape(value['scope'])+r'/resourceGroups/[^/?#%\s]+/providers/Microsoft.ApiManagement/service/[A-Za-z0-9-]{1,50}',service,re.I):
            raise ValueError('APIM service must belong to the approved subscription')
        pair=cid,service.casefold()
        if pair in seen:raise ValueError('duplicate APIM check/resource requirement')
        seen.add(pair)
        if cid==http:
            sampling=review.get('minimumSamplingPercentage')
            if type(sampling) not in (int,float) or not math.isfinite(sampling) or not 0<sampling<=100:
                raise ValueError('APIM sampling approval must be a positive percentage')
        if cid==verbose:
            apis=review.get('requiredApiIds')
            if (not isinstance(apis,list) or not apis or any(not isinstance(api,str) or not re.fullmatch(re.escape(service)+r'/apis/[A-Za-z0-9_.;=-]{1,256}',api,re.I) or api.rsplit('/',1)[-1] in ('.','..') for api in apis)
                    or len({api.casefold() for api in apis})!=len(apis)):
                raise ValueError('approved APIs must belong to the exact APIM service')
        if cid!=verbose or 'window' in review:
            window=review.get('window')
            if not isinstance(window,dict) or set(window)!={'start','end'}:raise ValueError('APIM receipt window is required')
            try:start,end=(datetime.fromisoformat(window[k].replace('Z','+00:00')) for k in ('start','end'))
            except (KeyError,TypeError,ValueError,AttributeError) as error:raise ValueError('invalid APIM receipt window') from error
            if start.utcoffset() is None or end.utcoffset() is None or not start<end<=datetime.now(timezone.utc) or end-start>timedelta(days=31):
                raise ValueError('APIM receipt window is future, reversed, unzoned or too large')


def azure_apim_protocol_review(value):
    """Accept only scoped owner requirements; native observations are forbidden."""
    from datetime import datetime, timezone
    from peaso.collectors.azure_apim_protocol_policy import _approved, SERVICE, SPEC, PROTOCOLS
    fields = {"status", "scope", "authorized_by", "document_id", "observed_at", "expires_at", "apim_protocols"}
    _scoped(value, fields, r"/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
    if set(value) != fields:
        raise ValueError("APIM protocol owner identity and dates are required")
    _, services = _approved({"compliance_policy": {"sw23": value}}, value["scope"], datetime.now(timezone.utc).isoformat())
    if not services:
        raise ValueError("APIM protocol service requirements are required")
    for service_id, policy in value["apim_protocols"].items():
        service_pattern = re.escape(value["scope"]) + r"/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft.ApiManagement/service/[A-Za-z0-9-]{1,50}"
        if (not SERVICE.fullmatch(service_id) or not re.fullmatch(service_pattern, service_id, re.I)
                or any(segment in (".", "..") for segment in service_id.split("/"))):
            raise ValueError("APIM service must belong to the approved subscription")
        if set(policy) != {"proposed_spec_sha256", "apis"} or policy["proposed_spec_sha256"] != SPEC:
            raise ValueError("APIM protocol rule requires the frozen specification")
        apis = policy["apis"]
        if not isinstance(apis, dict):
            raise ValueError("APIM protocol API requirements must be an object")
        seen = set()
        for api_id, rule in apis.items():
            if (not re.fullmatch(re.escape(service_id) + r"/apis/[A-Za-z0-9_.=-]{1,128}(?:;rev=[A-Za-z0-9][A-Za-z0-9_.-]{0,79})?", api_id, re.I)
                    or api_id.rsplit("/", 1)[-1].split(";", 1)[0] in (".", "..")
                    or api_id.casefold() in seen):
                raise ValueError("APIM API requirement has a foreign or ambiguous identity")
            seen.add(api_id.casefold())
            if not isinstance(rule, dict) or set(rule) != {"expected_endpoint_type", "forbidden_protocols"}:
                raise ValueError("APIM protocol requirement contains unsupported fields")
            expected, forbidden = rule["expected_endpoint_type"], rule["forbidden_protocols"]
            if (not isinstance(expected, str) or expected not in PROTOCOLS or not isinstance(forbidden, list)
                    or any(not isinstance(item, str) or item not in PROTOCOLS for item in forbidden)
                    or len(set(forbidden)) != len(forbidden) or expected in forbidden):
                raise ValueError("APIM protocol requirement is unsupported or contradictory")
