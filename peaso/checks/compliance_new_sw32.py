"""Signed Azure scope predicates over complete, scoped snapshot evidence."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import base64
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get

SPECS = {'azure.cis.mysql_single_audit_log_events_connection': {'resource_kind': 'mysql_single_server',
                                                        'category': 'logging',
                                                        'severity': 'medium',
                                                        'title': 'Legacy MySQL single server audits '
                                                                 'connection events',
                                                        'remediation_hint': 'Azure portal > Azure Database '
                                                                            'for MySQL Single Server > '
                                                                            'Server parameters: Set '
                                                                            'audit_log_events to include '
                                                                            'CONNECTION on each legacy MySQL '
                                                                            'single server.',
                                                        'proposed_spec_sha256': '61602ee32d518e401840ad8b6df6239175bb2ea07e2e5a4ff2b74e4322b2d062',
                                                        'dependencies': ['mysql_single_server']},
 'azure.gap.container_registry_vulnerabilities_remediated': {'resource_kind': 'container_registry',
                                                             'category': 'vulnerability',
                                                             'severity': 'medium',
                                                             'title': 'Container registry image '
                                                                      'vulnerabilities are resolved',
                                                             'remediation_hint': 'Azure portal > Defender '
                                                                                 'for Cloud > '
                                                                                 'Recommendations: Remediate '
                                                                                 'vulnerable images and '
                                                                                 'confirm Defender registry '
                                                                                 'assessments return '
                                                                                 'Healthy.',
                                                             'proposed_spec_sha256': '167bad41e5e48760e7890c248fd8381e749cd52513d5a56a4e492786adfaf8fb',
                                                             'dependencies': ['container_registry']},
 'azure.other.acr_untagged_retention': {'resource_kind': 'container_registry',
                                        'category': 'recovery',
                                        'severity': 'medium',
                                        'title': 'ACR untagged manifest retention is configured',
                                        'remediation_hint': 'Enable ACR Premium untagged-manifest retention '
                                                            'and set days within the approved maximum; add '
                                                            'and verify deletion policy for tagged and other '
                                                            'artifacts covered by the frozen requirement.',
                                        'proposed_spec_sha256': 'da15092e57ea911e46a63e8b7dce69b3a5e98728f8b699965b33fe22cc419901',
                                        'dependencies': ['container_registry']},
 'azure_devops_project_1_2_8_6_fb0e5a8': {'resource_kind': 'devops_project',
                                          'category': 'identity',
                                          'severity': 'medium',
                                          'title': 'Azure DevOps repository URLs do not embed credentials',
                                          'remediation_hint': 'Remove credentials from the affected '
                                                              'repository clone URL and rotate any exposed '
                                                              'credential; update pipeline or '
                                                              'service-connection references that copied it.',
                                          'proposed_spec_sha256': 'a3e8f9ba047fc530292a423c79b19b8e370232fe0c98153b7b472c8fdc8bcf85',
                                          'dependencies': ['devops_project']},
 'azure_devops_project_6_5_5_2_2908a87': {'resource_kind': 'devops_project',
                                          'category': 'hardening',
                                          'severity': 'medium',
                                          'title': 'Limit deployment jobs per pipeline stage',
                                          'remediation_hint': 'Reduce the first deployment stage to one '
                                                              'deployment job and later stages to the '
                                                              'approved deploymentLimit; resolve templates '
                                                              'at fixed revisions.',
                                          'proposed_spec_sha256': '7bade4a9b58122abb72cbdfe9e6297b36eb51a0e51f6fab60a08d11c73e96285',
                                          'dependencies': ['devops_project']},
 'azure_cosmos_account_10_2_1_1_13_5c115b0': {'resource_kind': 'cosmos_account',
                                              'category': 'logging',
                                              'severity': 'medium',
                                              'title': 'Cosmos DB MongoDB API exports request logs',
                                              'remediation_hint': 'For each Cosmos Mongo API account enable '
                                                                  'MongoRequests or DataPlaneRequests; for '
                                                                  'each Mongo vCore cluster enable '
                                                                  'vCoreMongoRequests. Route the category to '
                                                                  'an approved Log Analytics, Storage or '
                                                                  'Event Hubs sink on that resource.',
                                              'proposed_spec_sha256': '791a53df8f0bd18f4446638d78796b0d91c8a19539b26fc3a62c291f85915bdb',
                                              'dependencies': ['cosmos_account', 'mongo_cluster']},
 'azure_cosmos_account_10_2_1_1_23_e04a63d': {'resource_kind': 'cosmos_account',
                                              'category': 'logging',
                                              'severity': 'medium',
                                              'title': 'Export Cosmos DB data-plane request logs',
                                              'remediation_hint': 'Azure portal > Cosmos DB > Diagnostic '
                                                                  'settings: Enable DataPlaneRequests on the '
                                                                  'account diagnostic setting and set '
                                                                  'workspaceId.',
                                              'proposed_spec_sha256': 'f48fb75d722264aa7674af2e2b01ee423a4652365ffd53350a13e8661c85fb83',
                                              'dependencies': ['cosmos_account']},
 'azure_role_assignment_7_2_1_14_6743a56': {'resource_kind': 'role_definition_and_assignment',
                                            'category': 'least_privilege',
                                            'severity': 'medium',
                                            'title': 'Assigned custom Azure roles avoid unrestricted '
                                                     'wildcard permissions',
                                            'remediation_hint': 'Replace root-assignable custom roles with '
                                                                'Actions ["*"] by narrowly scoped '
                                                                'definitions and reassign principals.',
                                            'proposed_spec_sha256': 'd4992a4b076005d07ed13aebcf75d61a3899f949446cc6fb13221d5e683c2a3e',
                                            'dependencies': ['role_assignment', 'role_definition']},
 'azure_role_assignment_aks_cluster_rbac_enabled_675305a': {'resource_kind': 'role_definition_and_assignment',
                                                            'category': 'least_privilege',
                                                            'severity': 'medium',
                                                            'title': 'Required custom Azure RBAC role '
                                                                     'assignments exist',
                                                            'remediation_hint': 'Azure portal > Access '
                                                                                'control (IAM) at the '
                                                                                'specified scope: create or '
                                                                                'restore the required custom '
                                                                                'role definition and assign '
                                                                                'it to the approved '
                                                                                'principal.',
                                                            'proposed_spec_sha256': 'daadccd427f51130932b4f60c02210dfe91ea34a90ceeb484118d5c3c976fc1d',
                                                            'dependencies': ['role_assignment',
                                                                             'role_definition']},
 'azure_c5_ops_20_01b': {'resource_kind': 'security_assessment',
                         'category': 'hardening',
                         'severity': 'medium',
                         'title': 'Classify closed Sentinel incidents',
                         'remediation_hint': 'In Microsoft Sentinel, classify and prioritize each incident '
                                             'according to the incident policy; fill classification reasons '
                                             'when required and review the underlying response records.',
                         'proposed_spec_sha256': '6b72ba5082bf1fa3d6b8c7a3c771e4b5c7cd845659502086099541c7d569d207',
                         'dependencies': ['sentinel_workspace']},
 'azure_c5_ops_25_02b': {'resource_kind': 'security_assessment',
                         'category': 'hardening',
                         'severity': 'medium',
                         'title': 'C5 vulnerability severity follows defined criteria',
                         'remediation_hint': 'Define and apply vulnerability severity criteria; correct the '
                                             'severity mapping for affected findings or custom assessments.',
                         'proposed_spec_sha256': 'feb949ed4746d3b7602a8db0c0858000b7750c5ff93c8f72a858b318af0659e3',
                         'dependencies': ['security_assessment', 'assessment_metadata']},
 'azure.cis.private_endpoint_should_mariadb_servers': {'resource_kind': 'mariadb_server',
                                                       'category': 'network',
                                                       'severity': 'medium',
                                                       'title': 'Use an approved MariaDB private endpoint',
                                                       'remediation_hint': 'For a remaining MariaDB server, '
                                                                           'Azure portal > Networking > '
                                                                           'Private endpoint connections: '
                                                                           'create and approve a private '
                                                                           'endpoint targeting the server; '
                                                                           'plan migration from the retired '
                                                                           'service.',
                                                       'proposed_spec_sha256': 'f49c1951a9d5c3cf9a7b9b746c747aa45fa0862c82a78540c664c443afb3b466',
                                                       'dependencies': ['mariadb_server']},
 'azure.other.vault_key_approved_algorithm': {'resource_kind': 'vault_key',
                                              'category': 'hardening',
                                              'severity': 'high',
                                              'title': 'Use approved Key Vault key algorithms',
                                              'remediation_hint': 'Replace disallowed key versions with '
                                                                  'approved RSA-2048+ or EC-P256+ keys; for '
                                                                  'imported keys, obtain certified-HSM '
                                                                  'provenance evidence before approval.',
                                              'proposed_spec_sha256': 'aef68595b78e919a0b0854076696ecac660d7863acc3c98a0063e67b2ace0a89',
                                              'dependencies': ['vault_key']},
 'azure.other.monitor_dashboard_access': {'resource_kind': 'dashboard',
                                          'category': 'hardening',
                                          'severity': 'medium',
                                          'title': 'Monitoring dashboards restrict viewers',
                                          'remediation_hint': 'Azure portal > dashboard/workbook > Access '
                                                              'control (IAM): remove broad Reader grants at '
                                                              'resource/ancestor scope, resolve group '
                                                              'members and disable public sharing; grant '
                                                              'approved viewers only.',
                                          'proposed_spec_sha256': '636283c522b9a25490bba90ab0aa3c912dbefd7dc4ca477630f36bd942906f2a',
                                          'dependencies': ['dashboard']},
 'azure.other.vnet_peering_allowlist': {'resource_kind': 'vnet',
                                        'category': 'network',
                                        'severity': 'high',
                                        'title': 'VNet peerings target approved networks',
                                        'remediation_hint': 'Remove unapproved peerings and enforce a deny '
                                                            'policy for peering requests to unapproved '
                                                            'remote VNet IDs.',
                                        'proposed_spec_sha256': 'd2cb0b28f63bddb9d4f7a42cef4c4ff2af3383d651d2b2c0dda126d655d0c95b',
                                        'dependencies': ['vnet']}}

_ARM = re.compile(r"^/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/([^/]+/[^/]+)/[^/]+(?:/.*)?$", re.I)


def _scope(index, item):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"/subscriptions/[^/]+", scope, re.I) or get(item, "scope", str).casefold() != scope.casefold():
        raise Unavailable("foreign or malformed subscription scope")
    return scope



def _assessment_arm_identity(rid, scope):
    """Assessment extensions can target a subscription, RG or nested ARM resource."""
    if not rid.startswith('/') or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in '\\?#%' for c in rid):
        return False
    parts = rid[1:].split('/')
    if any(not p or p in ('.', '..') for p in parts):
        return False
    if len(parts) < 6 or parts[0].casefold() != 'subscriptions' or ('/subscriptions/' + parts[1]).casefold() != scope.casefold():
        return False
    tail = parts[2:]
    if tail[0].casefold() == 'resourcegroups':
        if len(tail) < 6:
            return False
        tail = tail[2:]
    providers = []
    while tail:
        if tail[0].casefold() != 'providers':
            return False
        boundary = next((i for i, value in enumerate(tail[1:], 1) if value.casefold() == 'providers'), len(tail))
        segment = tail[1:boundary]
        if (len(segment) < 3 or len(segment) % 2 != 1 or
                not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+', segment[0])):
            return False
        providers.append(segment)
        tail = tail[boundary:]
    # Exact final extension, not a matching ancestor or subassessment child.
    final = providers[-1]
    return (len(final) == 3 and '/'.join(final[:2]).casefold() == 'microsoft.security/assessments'
            and not any('/'.join(p[:2]).casefold() == 'microsoft.security/assessments' for p in providers[:-1]))


def _inventory(index, kind, scope, resource_type=None):
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("missing or ambiguous " + kind + " inventory")
    envelope = get(envelopes[0], "type", str)
    if envelope != kind or get(envelopes[0], "scope", str).casefold() != scope.casefold():
        raise Unavailable("foreign " + kind + " collection")
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    declared = get(envelopes[0], "items", list)
    if len(wrappers) != len(rows) or len(declared) != len(rows):
        raise Unavailable("inconsistent " + kind + " inventory")
    seen = set()
    for wrapper, native, row in zip(wrappers, declared, rows):
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str).casefold() != scope.casefold()
                or get(wrapper, "data", dict) != row or native != row):
            raise Unavailable("foreign or inconsistent " + kind + " row")
        rid = get(row, "id", str)
        if rid.casefold().startswith("/subscriptions/") and not rid.casefold().startswith(scope.casefold() + "/"):
            raise Unavailable("foreign " + kind + " subscription identity")
        if resource_type:
            if resource_type.casefold() == "microsoft.security/assessments":
                valid = _assessment_arm_identity(rid, scope)
            else:
                match = _ARM.fullmatch(rid)
                valid = bool(match and ("/subscriptions/" + match.group(1)).casefold() == scope.casefold()
                             and match.group(2).casefold() == resource_type.casefold())
            if not valid:
                raise Unavailable("foreign " + kind + " ARM identity")
        if rid.casefold() in seen:
            raise Unavailable("duplicate " + kind + " identity")
        seen.add(rid.casefold())
    return rows


def _children(row, field, path):
    coverage = get(row, "_coverage." + field + ".status", str)
    if coverage not in ("collected", "empty"):
        raise Unavailable("incomplete " + field)
    children = get(row, field, list)
    if (coverage == "empty") != (not children):
        raise Unavailable("inconsistent " + field + " coverage")
    seen = set()
    for child in children:
        cid = get(child, "id", str)
        if not cid.casefold().startswith((get(row, "id", str) + "/" + path + "/").casefold()) or cid.casefold() in seen:
            raise Unavailable("foreign or duplicate " + field + " child")
        seen.add(cid.casefold())
    return children


def _devops_children(project, field):
    status = get(project, "_coverage." + field + ".status", str)
    if status not in ("collected", "empty"):
        raise Unavailable("incomplete DevOps " + field + " pages")
    children = get(project, field, list)
    if (status == "empty") != (not children):
        raise Unavailable("inconsistent DevOps child coverage")
    seen = set()
    for child in children:
        identity = str(get(child, "id"))
        if not identity or get(child, "projectId", str).casefold() != get(project, "id", str).casefold() or identity.casefold() in seen:
            raise Unavailable("foreign or duplicate DevOps child")
        seen.add(identity.casefold())
    return children


def _policy(index, key):
    context = get(index, "context", dict)
    policy = get(context, "metadata.compliance_policy.sw32", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str).casefold() != get(context, "scope", str).casefold():
        raise Unavailable("unscoped or incomplete sw32 policy")
    return get(policy, key)


def _ids(value):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise Unavailable("malformed ID policy")
    return {x.casefold() for x in value}


def _aggregate(rows, evaluate, *, empty_na=False, empty_reason="complete applicable inventory empty"):
    if not rows and empty_na:
        return "NOT_APPLICABLE", {"reason": empty_reason}
    failures, uncertain = [], []
    for row in rows:
        rid = get(row, "id", str)
        try:
            state = evaluate(row)
            if state is True:
                failures.append(rid)
            elif state is None:
                uncertain.append(rid)
        except Unavailable:
            uncertain.append(rid)
    if failures:
        return result(True, failed_ids=failures, unresolved_ids=uncertain)
    if uncertain:
        return unknown("one or more applicable resources unresolved", unresolved_ids=uncertain)
    return result(False, assessed_count=len(rows))


def _mysql(index, scope):
    rows = _inventory(index, "mysql_single_server", scope, "Microsoft.DBforMySQL/servers")
    def check(row):
        configurations = _children(row, "configurations", "configurations")
        values = {}
        for config in configurations:
            name = get(config, "name", str).casefold()
            if name in values:
                raise Unavailable("duplicate MySQL configuration")
            values[name] = get(config, "properties.value", str)
        if not {"audit_log_enabled", "audit_log_events"} <= values.keys():
            return True
        enabled = values["audit_log_enabled"].upper()
        if enabled not in ("ON", "OFF"):
            raise Unavailable("unrecognized audit enabled value")
        events = [token.strip() for token in values["audit_log_events"].split(",")]
        if not events or any(not re.fullmatch(r"[A-Z_]+", token) for token in events):
            raise Unavailable("malformed audit event list")
        return enabled == "OFF" or "CONNECTION" not in events
    return _aggregate(rows, check, empty_na=True)


def _retention(index, scope):
    rows = _inventory(index, "container_registry", scope, "Microsoft.ContainerRegistry/registries")
    if rows and all(get(row, "sku.name", str) in ("Basic", "Standard") for row in rows):
        return "NOT_APPLICABLE", {"reason": "complete registry inventory has no Premium registry"}
    def check(row):
        sku = get(row, "sku.name", str)
        if sku in ("Basic", "Standard"):
            return False  # Outside the Premium-only setting, not evidence of full artifact policy.
        if sku != "Premium":
            raise Unavailable("unrecognized ACR SKU")
        status = get(row, "properties.policies.retentionPolicy.status", str)
        days = get(row, "properties.policies.retentionPolicy.days", int)
        if status not in ("enabled", "disabled") or days < 0:
            raise Unavailable("malformed ACR retention setting")
        if status == "disabled":
            return True
        maximum = _policy(index, "acr_max_untagged_days")
        if type(maximum) is not int or maximum < 1:
            raise Unavailable("approved ACR retention maximum absent")
        return days > maximum
    # An enabled untagged-manifest setting alone cannot PASS the artifact-deletion requirement.
    outcome = _aggregate(rows, check, empty_na=True)
    if outcome[0] == "PASS":
        return unknown("tagged and other artifact retention/deletion evidence unavailable", untagged_manifest_signal="PRESENT")
    return outcome


def _urls(index, scope):
    projects = _inventory(index, "devops_project", scope)
    def check(project):
        proof = get(project, "_provenance", dict)
        if any("native_devops_git_schema" in p.get("_provenance", {}) for p in projects):
            from peaso.azure_devops_git_policy import evaluate_project
            common = projects[0].get("_provenance", {})
            metadata = get(index, "context.metadata", dict)
            if any(proof.get(key) != common.get(key) for key in ("organization", "capture_id")) or any(
                    not isinstance(metadata.get(key), str) or proof.get(key) != metadata[key]
                    for key in ("credential_context_id", "customer_context_id")):
                raise Unavailable("native DevOps capture or credential binding mismatch")
            return evaluate_project(project, scope, [p["id"] for p in projects])
        if (get(proof, "api_version", str) != "7.1" or get(proof, "includeHidden", bool) is not True
                or get(proof, "includeAllUrls", bool) is not True):
            raise Unavailable("DevOps Git listing options unresolved")
        repos = _devops_children(project, "repositories")
        if not repos:
            return False
        uncertain = False
        for repo in repos:
            try:
                urls = [get(repo, "remoteUrl", str)] + get(repo, "validRemoteUrls", list)
                if not urls or any(not isinstance(u, str) or not u for u in urls):
                    raise Unavailable("missing clone URL")
                for url in urls:
                    parsed = urlsplit(url)
                    if parsed.scheme not in ("https", "http", "ssh") or not parsed.netloc or not parsed.hostname or parsed.port == 0:
                        raise Unavailable("malformed clone URL")
                    if "@" in parsed.netloc:
                        return True
            except (Unavailable, ValueError):
                uncertain = True
        return None if uncertain else False
    if not projects:
        return "NOT_APPLICABLE", {"reason": "complete project inventory empty"}
    outcome = _aggregate(projects, check)
    if outcome[0] == "PASS" and all(not get(p, "repositories", list) for p in projects):
        return "NOT_APPLICABLE", {"reason": "complete repository inventory empty"}
    return outcome


def _pipelines(index, scope):
    projects = _inventory(index, "devops_project", scope)
    limit = _policy(index, "later_stage_deployment_limit")
    if limit is not None and (type(limit) is not int or limit < 0):
        raise Unavailable("malformed later-stage deployment limit")
    def check(project):
        pipelines = _devops_children(project, "pipelines")
        uncertain = False
        for pipeline in pipelines:
            try:
                revision = get(pipeline, "resolved_revision", str)
                if not revision or get(pipeline, "templates_complete", bool) is not True or get(pipeline, "dynamic_expressions_resolved", bool) is not True:
                    raise Unavailable("pipeline YAML not fully resolved")
                stages = get(pipeline, "deployment_stages", list)
                if not stages:
                    raise Unavailable("deployment stage inventory absent")
                for n, stage in enumerate(stages):
                    count = get(stage, "deployment_job_count", int)
                    if count < 0:
                        raise Unavailable("negative deployment job count")
                    maximum = 1 if n == 0 else limit
                    if maximum is None:
                        raise Unavailable("later stage limit absent")
                    if count > maximum:
                        return True
            except Unavailable:
                uncertain = True
        return None if uncertain else False
    return _aggregate(projects, check, empty_na=True)


def _diagnostics(index, scope, *, mongo):
    accounts = _inventory(index, "cosmos_account", scope, "Microsoft.DocumentDB/databaseAccounts")
    clusters = _inventory(index, "mongo_cluster", scope, "Microsoft.DocumentDB/mongoClusters") if mongo else []
    approved = None if mongo else _ids(_policy(index, "approved_cosmos_workspaces"))
    applicable = []
    for row in accounts:
        if mongo:
            capabilities = get(row, "properties.capabilities", list)
            if any(not isinstance(c, dict) for c in capabilities):
                raise Unavailable("malformed Cosmos capabilities")
            if not any(get(c, "name", str) == "EnableMongo" for c in capabilities):
                continue
        applicable.append((row, {"MongoRequests", "DataPlaneRequests"} if mongo else {"DataPlaneRequests"}))
    applicable.extend((row, {"vCoreMongoRequests"}) for row in clusters)
    if not applicable:
        return "NOT_APPLICABLE", {"reason": "complete Mongo inventory empty"} if mongo else result(False, assessed_count=0)
    def check(entry):
        row, categories = entry
        supported = get(row, "supported_log_categories", list)
        if any(not isinstance(value, str) for value in supported) or not categories.intersection(supported):
            raise Unavailable("supported diagnostic category unresolved")
        settings = _children(row, "diagnosticSettings", "providers/Microsoft.Insights/diagnosticSettings")
        uncertain = False
        found = False
        for setting in settings:
            try:
                props = get(setting, "properties", dict)
                logs = get(props, "logs", list)
                if any(not isinstance(log, dict) for log in logs):
                    raise Unavailable("malformed diagnostic logs")
                qualifying = False
                for log in logs:
                    if get(log, "enabled", bool):
                        category, group = log.get("category"), log.get("categoryGroup")
                        if category is not None and group is not None:
                            raise Unavailable("ambiguous diagnostic category and group")
                        if category is not None:
                            if not isinstance(category, str) or not category:
                                raise Unavailable("malformed diagnostic category")
                            qualifying |= category in categories
                        elif group is not None:
                            if not isinstance(group, str) or not group:
                                raise Unavailable("malformed diagnostic category group")
                            # Group membership must be independently resolved.
                            members = get(log, "resolvedCategories", list)
                            if (any(not isinstance(x, str) or not x for x in members)
                                    or len(members) != len(set(members))
                                    or not set(members) <= set(supported)):
                                raise Unavailable("malformed category group")
                            qualifying |= bool(categories.intersection(members))
                        else:
                            raise Unavailable("diagnostic category or group absent")
                if qualifying:
                    if mongo:
                        sinks = (("workspaceId", "Microsoft.OperationalInsights/workspaces"),
                                 ("storageAccountId", "Microsoft.Storage/storageAccounts"),
                                 ("eventHubAuthorizationRuleId", "Microsoft.EventHub/namespaces"))
                        if any(isinstance(props.get(key), str) and (match := _ARM.fullmatch(props[key]))
                               and match.group(2).casefold() == typ.casefold()
                               and (key != "eventHubAuthorizationRuleId" or "/authorizationRules/" in props[key])
                               for key, typ in sinks):
                            found = True
                            continue
                        raise Unavailable("diagnostic sink validity unresolved")
                    workspace = get(props, "workspaceId", str)
                    if workspace.casefold() in approved:
                        found = True
            except Unavailable:
                uncertain = True
        return None if uncertain else not found
    # Explicit aggregate over exact account/cluster identities.
    failures, uncertain = [], []
    for entry in applicable:
        try:
            state = check(entry)
            if state is True:
                failures.append(get(entry[0], "id", str))
            elif state is None:
                uncertain.append(get(entry[0], "id", str))
        except Unavailable:
            uncertain.append(get(entry[0], "id", str))
    if failures:
        return result(True, failed_ids=failures, unresolved_ids=uncertain)
    if uncertain:
        return unknown("Cosmos diagnostic export unresolved", unresolved_ids=uncertain)
    return result(False, assessed_count=len(applicable))


def _registry_vulnerabilities(index, scope):
    registries = _inventory(index, "container_registry", scope, "Microsoft.ContainerRegistry/registries")
    assessment_key = _policy(index, "registry_vulnerability_assessment_key")
    maximum = _policy(index, "max_registry_scan_age_seconds")
    if not isinstance(assessment_key, str) or not assessment_key or type(maximum) is not int or maximum <= 0:
        raise Unavailable("registry assessment key or scan-age policy missing")
    captured = _time(get(index, "context.created_at", str))
    def check(registry):
        manifests = _children(registry, "imageManifests", "imageManifests")
        findings = _children(registry, "vulnerabilitySubAssessments", "vulnerabilitySubAssessments")
        parent = get(registry, "vulnerabilityAssessment", dict)
        if get(parent, "name", str).casefold() != assessment_key.casefold():
            raise Unavailable("registry assessment key mismatch")
        parent_state = get(parent, "properties.status.code", str)
        if parent_state not in ("Healthy", "Unhealthy", "NotApplicable"):
            raise Unavailable("unsupported registry assessment status")
        current = set()
        for manifest in manifests:
            repo, digest = get(manifest, "repositoryName", str), get(manifest, "imageDigest", str)
            if not repo or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
                raise Unavailable("malformed current ACR manifest identity")
            current.add((repo, digest.casefold()))
        covered = set()
        unhealthy = False
        for finding in findings:
            if get(finding, "assessmentKey", str).casefold() != assessment_key.casefold():
                raise Unavailable("foreign assessment generation")
            rid = get(finding, "properties.resourceDetails.id", str)
            repo = get(finding, "properties.additionalData.repositoryName", str)
            digest = get(finding, "properties.additionalData.imageDigest", str).casefold()
            identity = (repo, digest)
            if rid.casefold() != get(registry, "id", str).casefold() or identity not in current:
                raise Unavailable("unresolved subassessment image join")
            age = (captured - _time(get(finding, "properties.timeGenerated", str))).total_seconds()
            if age < 0 or age > maximum:
                raise Unavailable("stale or future image scan")
            state = get(finding, "properties.status.code", str)
            if state not in ("Healthy", "Unhealthy", "NotApplicable"):
                raise Unavailable("unrecognized subassessment status")
            covered.add(identity)
            unhealthy |= state == "Unhealthy"
        if unhealthy:
            return True
        if covered != current or parent_state not in ("Healthy", "NotApplicable"):
            raise Unavailable("per-image scan coverage or healthy parent unresolved")
        return False
    return _aggregate(registries, check, empty_na=True)


def _role_wildcard(index, scope):
    roles = _inventory(index, "role_definition", scope)
    assignments = _inventory(index, "role_assignment", scope)
    coverage = _policy(index, "rbac_relevant_scopes_complete")
    if coverage is not True:
        raise Unavailable("ancestor and descendant RBAC scope coverage unresolved")
    by_id = {get(r, "id", str).casefold(): r for r in roles}
    if len(by_id) != len(roles):
        raise Unavailable("duplicate role definitions")
    failures = []
    for assignment in assignments:
        _assignment_scope(assignment, scope)
        role_id = get(assignment, "properties.roleDefinitionId", str).casefold()
        role = by_id.get(role_id)
        if role is None:
            raise Unavailable("role definition join unresolved")
        role_type = get(role, "properties.type", str)
        if role_type not in ("CustomRole", "BuiltInRole"):
            raise Unavailable("unrecognized role type")
        if role_type != "CustomRole":
            continue
        scopes = get(role, "properties.assignableScopes", list)
        permissions = get(role, "properties.permissions", list)
        if any(not isinstance(x, str) for x in scopes) or any(not isinstance(x, dict) for x in permissions):
            raise Unavailable("malformed custom role definition")
        actions = [get(p, "actions", list) for p in permissions]
        if any(any(not isinstance(action, str) for action in group) for group in actions):
            raise Unavailable("malformed custom role action")
        if "/" in scopes and any("*" in group for group in actions):
            failures.append(get(assignment, "id", str))
    return result(bool(failures), failed_ids=failures, assessed_assignments=len(assignments))


def _required_roles(index, scope):
    required = _policy(index, "required_role_assignments")
    if not isinstance(required, list):
        raise Unavailable("required RBAC tuple policy malformed")
    if _policy(index, "rbac_relevant_scopes_complete") is not True:
        raise Unavailable("ancestor and management-group assignment scope unresolved")
    assignments = _inventory(index, "role_assignment", scope)
    roles = _inventory(index, "role_definition", scope)
    by_id = {get(r, "id", str).casefold(): r for r in roles}
    if len(by_id) != len(roles):
        raise Unavailable("duplicate role definition")
    present = set()
    for assignment in assignments:
        _assignment_scope(assignment, scope)
        props = get(assignment, "properties", dict)
        triple = (get(props, "principalId", str).casefold(), get(props, "roleDefinitionId", str).casefold(), get(props, "scope", str).casefold())
        if triple[1] not in by_id:
            raise Unavailable("role definition join unresolved")
        present.add(triple)
    missing = []
    for requirement in required:
        triple = tuple(get(requirement, key, str).casefold() for key in ("principalId", "roleDefinitionId", "scope"))
        if not _scope_authorized(triple[2], scope):
            raise Unavailable("required assignment scope foreign")
        role = by_id.get(triple[1])
        if role is None or get(role, "properties.type", str) != "CustomRole":
            raise Unavailable("required custom role definition unresolved")
        if triple not in present:
            missing.append(triple)
    return result(bool(missing), missing_required_tuples=missing, required_count=len(required))


def _scope_authorized(value, scope):
    return value.casefold() == scope.casefold() or value.casefold().startswith(scope.casefold() + "/") or value.casefold().startswith("/providers/microsoft.management/managementgroups/")


def _assignment_scope(assignment, scope):
    value = get(assignment, "properties.scope", str)
    if not _scope_authorized(value, scope):
        raise Unavailable("foreign RBAC assignment scope")


def _mariadb(index, scope):
    servers = _inventory(index, "mariadb_server", scope, "Microsoft.DBforMariaDB/servers")
    def check(server):
        connections = _children(server, "privateEndpointConnections", "privateEndpointConnections")
        approved = False
        for connection in connections:
            if get(connection, "properties.privateLinkServiceConnectionState.status", str) == "Approved":
                target = get(connection, "properties.privateLinkServiceId", str)
                if target.casefold() != get(server, "id", str).casefold():
                    raise Unavailable("private endpoint targets another server")
                get(connection, "properties.privateEndpoint.id", str)
                approved = True
        if not approved:
            return True
        try:
            public = get(server, "properties.publicNetworkAccess", str)
        except Unavailable:
            public = None
        if public == "Disabled":
            return False
        if public in ("Enabled", None):
            restricted = get(server, "network_restriction_evidence", dict)
            if get(restricted, "unrestricted_public_ingress", bool):
                return True
            if get(restricted, "approved_networks_only", bool):
                return False
            raise Unavailable("public access restriction unresolved")
        raise Unavailable("MariaDB public network access unknown")
    return _aggregate(servers, check, empty_na=True)


def _keys(index, scope):
    keys = _inventory(index, "vault_key", scope, "Microsoft.KeyVault/vaults")
    policy = _policy(index, "approved_key_algorithms")
    if not isinstance(policy, dict) or get(policy, "industry_standard_confirmed", bool) is not True:
        raise Unavailable("approved key algorithm policy unresolved")
    min_rsa = get(policy, "minimum_rsa_bits", int)
    curves = _ids(get(policy, "approved_ec_curves", list))
    if min_rsa < 2048 or not curves:
        raise Unavailable("unsafe or missing key algorithm policy")
    def check(key):
        versions = _children(key, "versions", "versions")
        if not versions:
            raise Unavailable("key has no version inventory")
        uncertain = False
        for version in versions:
            try:
                if get(version, "attributes.enabled", bool) is not True:
                    continue
                if get(version, "encryption_use", bool) is not True:
                    continue
                material = get(version, "key", dict)
                kty = get(material, "kty", str)
                if kty not in {"RSA", "RSA-HSM", "EC", "EC-HSM", "oct", "oct-HSM"}:
                    raise Unavailable("unknown native key type")
                if kty in {"RSA", "RSA-HSM"}:
                    modulus = get(material, "n", str)
                    if not re.fullmatch(r"[A-Za-z0-9_-]+", modulus):
                        raise Unavailable("malformed RSA modulus")
                    bits = int.from_bytes(base64.urlsafe_b64decode(modulus + "=" * (-len(modulus) % 4)), "big").bit_length()
                    if bits < min_rsa:
                        return True
                elif kty in {"EC", "EC-HSM"}:
                    if get(material, "crv", str).casefold() not in curves:
                        return True
                else:
                    return True
                if get(version, "algorithm_policy_approved", bool) is not True:
                    return True
                origin = get(version, "import_provenance", str)
                if origin == "imported":
                    if get(version, "certified_hsm_provenance", bool) is not True:
                        return True
                elif origin != "generated":
                    raise Unavailable("key import provenance unresolved")
            except (Unavailable, ValueError):
                uncertain = True
        return None if uncertain else False
    return _aggregate(keys, check, empty_na=True)


def _dashboard(index, scope):
    dashboards = _inventory(index, "dashboard", scope)
    sensitive = _ids(_policy(index, "sensitive_dashboard_ids"))
    approved = _ids(_policy(index, "approved_dashboard_viewers"))
    known = {get(d, "id", str).casefold() for d in dashboards}
    if not sensitive <= known:
        raise Unavailable("classified dashboard inventory incomplete")
    selected = [d for d in dashboards if get(d, "id", str).casefold() in sensitive]
    def check(row):
        access = get(row, "effectiveAccess", dict)
        viewers = get(access, "viewers", list)
        if any(not isinstance(v, str) or not v for v in viewers):
            raise Unavailable("malformed effective viewer")
        if any(v.casefold() not in approved for v in viewers):
            return True
        if get(access, "public_share_enabled", bool):
            return True
        for key in ("ancestor_scopes_complete", "role_definitions_complete", "conditions_resolved", "transitive_groups_complete", "alternate_sharing_complete"):
            if get(access, key, bool) is not True:
                raise Unavailable("effective access coverage unresolved")
        return False
    return _aggregate(selected, check, empty_na=True)


def _vnet(index, scope):
    vnets = _inventory(index, "vnet", scope, "Microsoft.Network/virtualNetworks")
    try:
        prevention = _policy(index, "unapproved_peering_prevention")
        if not isinstance(prevention, dict):
            raise Unavailable("peering prevention evidence malformed")
        succeeded = get(prevention, "controlled_unapproved_request_succeeded", bool)
    except Unavailable:
        prevention, succeeded = None, False
    if succeeded:
        return result(True, reason="controlled unapproved peering request succeeded")
    approved = _ids(_policy(index, "approved_peer_ids"))
    def check(vnet):
        peerings = _children(vnet, "virtualNetworkPeerings", "virtualNetworkPeerings")
        for peering in peerings:
            state = get(peering, "properties.peeringState", str)
            if state not in ("Connected", "Initiated", "Disconnected"):
                raise Unavailable("unrecognized VNet peering state")
            target = get(peering, "properties.remoteVirtualNetwork.id", str)
            if not re.fullmatch(r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+", target, re.I):
                raise Unavailable("malformed remote VNet identity")
            if target.casefold() not in approved:
                return True
        return False
    outcome = _aggregate(vnets, check, empty_na=True)
    if outcome[0] != "PASS":
        return outcome
    if prevention is None:
        raise Unavailable("peering prevention evidence unavailable")
    if get(prevention, "enforced_deny_policy", bool) or get(prevention, "controlled_unapproved_request_rejected", bool):
        return result(False, assessed_vnets=len(vnets))
    return unknown("request-time prevention not proven", configured_peerings="approved")


def _time(value):
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("timezone missing")
        return instant.astimezone(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise Unavailable("malformed timestamp") from exc


def _incidents(index, scope):
    workspaces = _inventory(index, "sentinel_workspace", scope)
    if not workspaces:
        return unknown("no Sentinel incident detection and handling coverage established")
    policy = _policy(index, "incident_review")
    start, end = _time(get(policy, "start", str)), _time(get(policy, "end", str))
    if start >= end or get(policy, "approved", bool) is not True:
        raise Unavailable("incident review window unresolved")
    allowed = _ids(get(policy, "allowed_classifications", list))
    priorities = _ids(get(policy, "allowed_priorities", list))
    def check(workspace):
        incidents = _children(workspace, "incidents", "providers/Microsoft.SecurityInsights/incidents")
        uncertain = False
        observed = 0
        for incident in incidents:
            try:
                props = get(incident, "properties", dict)
                changed = _time(get(props, "lastModifiedTimeUtc", str))
                if not start <= changed < end:
                    continue
                status = get(props, "status", str)
                if status not in ("New", "Active", "Closed"):
                    raise Unavailable("incident status unrecognized")
                observed += 1
                classification = get(props, "classification", str)
                priority = get(props, "severity", str)
                if classification.casefold() not in allowed or priority.casefold() not in priorities:
                    return True
                reason_required = get(incident, "classification_reason_required", bool)
                if reason_required and not get(props, "classificationReason", str):
                    return True
                process = get(incident, "process_evidence", dict)
                for step in ("identified", "recorded", "prioritized", "instructions_followed"):
                    state = get(process, step, str)
                    if state == "failed":
                        return True
                    if state != "verified":
                        raise Unavailable("incident process step unresolved")
            except Unavailable:
                uncertain = True
        if not observed and get(workspace, "continuous_detection_and_handling_coverage", bool) is not True:
            uncertain = True
        return None if uncertain else False
    return _aggregate(workspaces, check, empty_na=False)


def _severity(index, scope):
    assessments = _inventory(index, "security_assessment", scope, "Microsoft.Security/assessments")
    metadata = _inventory(index, "assessment_metadata", scope)
    policy = _policy(index, "vulnerability_severity_criteria")
    if get(policy, "approved", bool) is not True or get(policy, "finding_coverage_complete", bool) is not True:
        raise Unavailable("severity criteria or finding coverage unresolved")
    by_key = {get(m, "name", str): m for m in metadata}
    if len(by_key) != len(metadata):
        raise Unavailable("duplicate assessment metadata")
    def check(assessment):
        key = get(assessment, "name", str)
        state = get(assessment, "properties.status.code", str)
        if state not in ("Healthy", "Unhealthy", "NotApplicable"):
            raise Unavailable("unrecognized assessment status")
        if state == "NotApplicable":
            return False
        meta = by_key.get(key)
        if meta is None:
            raise Unavailable("assessment metadata join missing")
        severity = get(meta, "properties.severity", str)
        if severity not in ("Low", "Medium", "High"):
            raise Unavailable("optional severity absent or unrecognized")
        evidence = get(assessment, "severity_criteria_evidence", dict)
        if get(evidence, "criteria_version", str) != get(policy, "version", str):
            raise Unavailable("criteria version mismatch")
        match = get(evidence, "assigned_severity_matches_criteria", bool)
        return not match
    return _aggregate(assessments, check, empty_na=False)

_EVALUATORS = {
    "azure.cis.mysql_single_audit_log_events_connection": _mysql,
    "azure.gap.container_registry_vulnerabilities_remediated": _registry_vulnerabilities,
    "azure.other.acr_untagged_retention": _retention,
    "azure_devops_project_1_2_8_6_fb0e5a8": _urls,
    "azure_devops_project_6_5_5_2_2908a87": _pipelines,
    "azure_cosmos_account_10_2_1_1_13_5c115b0": lambda i, s: _diagnostics(i, s, mongo=True),
    "azure_cosmos_account_10_2_1_1_23_e04a63d": lambda i, s: _diagnostics(i, s, mongo=False),
    "azure_role_assignment_7_2_1_14_6743a56": _role_wildcard,
    "azure_role_assignment_aks_cluster_rbac_enabled_675305a": _required_roles,
    "azure_c5_ops_20_01b": _incidents,
    "azure_c5_ops_25_02b": _severity,
    "azure.cis.private_endpoint_should_mariadb_servers": _mariadb,
    "azure.other.vault_key_approved_algorithm": _keys,
    "azure.other.monitor_dashboard_access": _dashboard,
    "azure.other.vnet_peering_allowlist": _vnet,
}


def _install(check_id, spec):
    native_category = spec["category"] if spec["category"] in {"hardening", "exposure", "least_privilege", "iam_graph", "network"} else "hardening"
    @register(check_id, "azure", native_category, spec["resource_kind"], spec["title"],
              spec["severity"], "CM-6", spec["remediation_hint"], target="scope",
              dependencies=spec["dependencies"])
    def evaluate(item, index):
        scope = _scope(index, item)
        return _EVALUATORS[check_id](index, scope)
    evaluate.__name__ = check_id.replace(".", "_")
    if native_category != spec["category"]:
        CHECKS[-1] = replace(CHECKS[-1], category=spec["category"])
    return evaluate

EVALUATORS = {check_id: _install(check_id, spec) for check_id, spec in SPECS.items()}
IDS = tuple(SPECS)
