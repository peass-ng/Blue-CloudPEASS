"""Signed GCP proposed checks implemented by the sw09 collector-aware wave."""
from __future__ import annotations

import re
import json
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_network

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects, full_representation, omitted


META = {'gcp.appengine.version_https_only': {'category': 'network',
                                      'description': 'Checks the App Engine Admin API '
                                                     'securityLevel on each handler of SERVING '
                                                     'versions; SECURE_ALWAYS redirects HTTP to '
                                                     'HTTPS. Missing or masked handler settings '
                                                     'cannot prove HTTPS enforcement.',
                                      'proposed_spec_sha256': '31bf24910d36ea78c6a82f402310a5504c4800e38585aff1d879dfaea1554dbe',
                                      'remediation_hint': 'Review handler routing with the service '
                                                          'owner, set secure: always in app.yaml '
                                                          'for the intended handlers, deploy a new '
                                                          'version, and verify the Admin API '
                                                          'securityLevel declaration.',
                                      'resource_kind': 'app_engine_version',
                                      'severity': 'high',
                                      'title': 'App Engine serving versions enforce HTTPS'},
 'gcp.sql.iam_database_authentication': {'category': 'hardening',
                                         'description': 'On supported Cloud SQL PostgreSQL and '
                                                        'MySQL instances, detects when users.list '
                                                        'contains no IAM database user; this '
                                                        'leaves database access dependent on '
                                                        'built-in credentials rather than IAM '
                                                        'identities.',
                                         'proposed_spec_sha256': '0fa6351e4358600196dc9658773cf10e4cece7acddc95bbe9cfe5b6a30c0b6b3',
                                         'remediation_hint': 'Create an IAM database user on the '
                                                             'Cloud SQL instance with gcloud sql '
                                                             'users create --type=CLOUD_IAM_USER '
                                                             'or CLOUD_IAM_SERVICE_ACCOUNT.',
                                         'resource_kind': 'sql_instance',
                                         'severity': 'medium',
                                         'title': 'Cloud SQL has an IAM database user'},
 'gcp_autoscaler_capacity_target': {'category': 'availability',
                                    'description': 'On autoscaler resources, detects when '
                                                   'utilizationTarget exceeds 0.8 or '
                                                   'maxNumReplicas cannot add at least one '
                                                   'instance above current size; this matters '
                                                   'because it can lead to service outage or '
                                                   'failed recovery.',
                                    'proposed_spec_sha256': 'f863fe5de239d95cacfaf54ec8ca29d724a8b89a8ff850e137172e8065d1e282',
                                    'remediation_hint': 'Lower '
                                                        'autoscalingPolicy.cpuUtilization.utilizationTarget '
                                                        'to 0.8 or less and raise maxNumReplicas '
                                                        'above the current MIG target size.',
                                    'resource_kind': 'autoscaler',
                                    'severity': 'medium',
                                    'title': 'Autoscaler cannot expand at 80 percent capacity'},
 'gcp_c5_tls_policy': {'category': 'encryption',
                       'description': 'On target proxy resources, detects when an in-scope HTTPS '
                                      'or SSL proxy has a policy allowing a TLS version/cipher '
                                      'below the approved minimum; this matters because it can '
                                      'lead to unprotected sensitive data.',
                       'proposed_spec_sha256': 'ed286edd189b2231b318a52ffc6f8dbbd18617ca3f78575c1cbc76d95377483c',
                       'remediation_hint': 'Attach an SSL policy with approved minTlsVersion and '
                                           'cipher profile to every in-scope target HTTPS/SSL '
                                           'proxy.',
                       'resource_kind': 'target_proxy',
                       'severity': 'medium',
                       'title': 'Approved frontend TLS policy'},
 'gcp_certificate_validity': {'category': 'encryption',
                              'description': 'On certificate resources, detects when expireTime is '
                                             'past or managed.state is not ACTIVE; this matters '
                                             'because it can lead to unprotected sensitive data.',
                              'proposed_spec_sha256': '6a623dc5d64f07b6de945273d5d7237f880b0e3a028e722f8ad67fa043220084',
                              'remediation_hint': 'Renew or replace expired Certificate Manager '
                                                  'certificates and attach an ACTIVE certificate '
                                                  'to the map entry.',
                              'resource_kind': 'certificate',
                              'severity': 'high',
                              'title': 'Managed certificate is expired or inactive'},
 'gcp_cloudbuild_trigger_trust': {'category': 'supply_chain',
                                  'description': 'On cloudbuild trigger resources, detects when an '
                                                 'enabled trigger uses a repository or service '
                                                 'account outside approved allowlists; this '
                                                 'matters because it can lead to unverifiable '
                                                 'software provenance.',
                                  'proposed_spec_sha256': 'fb317c2787af526c9c6a44c9bb9c98837c475bd28e07335fcec705b02ff80d16',
                                  'remediation_hint': 'Restrict enabled Cloud Build trigger '
                                                      'repository selectors and serviceAccount to '
                                                      'the approved source and identity lists.',
                                  'resource_kind': 'cloudbuild_trigger',
                                  'severity': 'high',
                                  'title': 'Cloud Build trigger accepts unapproved source'},
 'gcp_cloudsql_failed_attempts_lockout': {'category': 'identity',
                                          'description': 'Preserves the original lockout-or-rate-limit requirement. A positive configured-lockout verdict requires a dated explicitly approved customer-account responsibility boundary matching the entire complete API-visible account universe, and documented managed MySQL lockout on every account. It does not assert protection of provider-internal principals or observed runtime login behavior.',
                                          'proposed_spec_sha256': '7f007ab89daf6fcd67916ec56fdd29b35aff32d0770f3317d33c809e83a16c1d',
                                          'remediation_hint': "Establish the full in-scope authentication-account inventory and approved lockout or rate-limiting controls. For supported managed MySQL built-in accounts, review instance password-policy enablement and each user's passwordPolicy.enableFailedAttemptsCheck and positive allowedFailedAttempts; verify other authentication paths separately without inferring a violation from missing metadata.",
                                          'resource_kind': 'sql_instance',
                                          'severity': 'medium',
                                          'title': 'Cloud SQL protection against repeated failed sign-ins'},
 'gcp_compute_approved_image': {'category': 'compute',
                                'description': 'On instance resources, detects when a VM boot disk '
                                               'sourceImage is outside approved_image_projects; '
                                               'this matters because VMs may inherit unvetted '
                                               'operating system content.',
                                'proposed_spec_sha256': '518042836f9498a3e1f199accb53b806f2f7a28b3e72e7e55c79e1886c1c234f',
                                'remediation_hint': 'Replace the VM boot disk with an image from '
                                                    'approved_image_projects, then verify its '
                                                    'disk.sourceImage.',
                                'resource_kind': 'instance',
                                'severity': 'high',
                                'title': 'VM uses an unapproved image'},
 'gcp_gke_client_certificate_enabled': {'category': 'identity',
                                        'description': 'Records legacy GKE client-certificate '
                                                       'issuance for an owner-approved exception '
                                                       'review; disabling legacy issuance is the '
                                                       'recommended security posture.',
                                        'proposed_spec_sha256': '788f62a784cf46f983650da3e354ef6b2289e196dd037517e4847a7ad17f8699',
                                        'remediation_hint': 'Review legacy certificate '
                                                            'authentication with the cluster owner '
                                                            'and use modern GKE authentication; do '
                                                            'not enable certificate issuance '
                                                            'solely for this historical control.',
                                        'resource_kind': 'gke_cluster',
                                        'severity': 'medium',
                                        'title': 'GKE legacy client-certificate issuance requires '
                                                 'policy review'},
 'gcp_https_proxy_mtls_required': {'category': 'encryption',
                                   'description': 'On target https proxy resources, detects when '
                                                  'an HTTPS proxy lacks a server TLS policy '
                                                  'requiring REJECT_INVALID client certificates; '
                                                  'this matters because it can lead to unprotected '
                                                  'sensitive data.',
                                   'proposed_spec_sha256': '9a13a18ff4e298ca90e176a41355195492cd6d508ab5d1e9f60194a543b88913',
                                   'remediation_hint': 'Attach a Network Security serverTlsPolicy '
                                                       'to each HTTPS proxy with '
                                                       'mtlsPolicy.clientValidationMode=REJECT_INVALID.',
                                   'resource_kind': 'target_https_proxy',
                                   'severity': 'high',
                                   'title': 'HTTPS proxy does not require client certificates'},
 'gcp_network_auto_subnets_enabled': {'category': 'network',
                                      'description': 'On a VPC required to use automatic subnet '
                                                     'creation, detects '
                                                     'autoCreateSubnetworks=false; the VPC lacks '
                                                     'regional subnetworks required by the '
                                                     'approved design.',
                                      'proposed_spec_sha256': 'baee4c53108558634672b2aaaa0013b32e57e578d2aadfdf530184b65656094e',
                                      'remediation_hint': 'Set autoCreateSubnetworks=true on the '
                                                          'VPC only if automatic regional subnet '
                                                          'creation is the approved network '
                                                          'design.',
                                      'resource_kind': 'network',
                                      'severity': 'medium',
                                      'title': 'VPC automatically creates regional subnetworks '
                                               'where required'},
 'gcp_pci_firewall_2080b14f1361': {'category': 'network',
                                   'description': 'On firewall resources, detects when any active '
                                                  'ingress allow rule admits public source '
                                                  '0.0.0.0/0 or ::/0 for the ports and protocols '
                                                  'in scope; this matters because internet hosts '
                                                  'can connect to the allowed ports.',
                                   'proposed_spec_sha256': '0492786d4f15b0ec06330e86eb57d9e042864815ffb238d8eac9f509c78a2a18',
                                   'remediation_hint': 'Restrict firewall sourceRanges from '
                                                       '0.0.0.0/0 and ::/0 to approved CIDRs for '
                                                       'each allowed port/protocol.',
                                   'resource_kind': 'firewall',
                                   'severity': 'medium',
                                   'title': 'VPC firewall public ingress'},
 'gcp_pci_iam_policy_9a8ce875703d': {'category': 'logging',
                                     'description': 'On iam policy resources, detects when '
                                                    'effective auditConfigs omit the required '
                                                    'Pub/Sub Data Access log types; this matters '
                                                    'because Pub/Sub data access may not appear in '
                                                    'audit logs.',
                                     'proposed_spec_sha256': '2e15b4bf0d6053de740b6ebac702394241a61c999cc2a9f59c2d898e6e632c7b',
                                     'remediation_hint': 'Add effective Pub/Sub auditConfigs with '
                                                         'required DATA_READ and DATA_WRITE types '
                                                         'and remove relevant exemptions.',
                                     'resource_kind': 'iam_policy',
                                     'severity': 'medium',
                                     'title': 'Pub/Sub Data Access audit logging'},
 'gcp_pci_iam_policy_ca1281da7ab2': {'category': 'logging',
                                     'description': 'On iam policy resources, detects when '
                                                    'effective auditConfigs omit the required '
                                                    'Spanner Data Access log types; this matters '
                                                    'because Spanner data access may not appear in '
                                                    'audit logs.',
                                     'proposed_spec_sha256': '8beebc607b85d140d1a91893e1a7ceb75cc2ed8f136622fe87b5ccf7631228e6',
                                     'remediation_hint': 'Add effective Spanner auditConfigs with '
                                                         'required DATA_READ and DATA_WRITE types '
                                                         'and remove relevant exemptions.',
                                     'resource_kind': 'iam_policy',
                                     'severity': 'medium',
                                     'title': 'Spanner Data Access audit logging'},
 'gcp_resource_approved_location': {'category': 'data_residency',
                                    'description': 'On cloud asset resources, detects when a '
                                                   'collected resource location is absent from the '
                                                   'explicit approved_locations allowlist; this '
                                                   'matters because it can lead to processing '
                                                   'outside approved regions.',
                                    'proposed_spec_sha256': '0f5f46d8008cd59aa112912de3c4927c07436e682d4627e970282f34479f5766',
                                    'remediation_hint': 'Move resources to an approved location or '
                                                        'update the approved_locations policy for '
                                                        'explicitly authorized regions.',
                                    'resource_kind': 'cloud_asset',
                                    'severity': 'high',
                                    'title': 'Resource location is not approved'},
 'gcp_resource_label_inventory': {'category': 'asset_management',
                                  'description': 'On cloud asset resources, detects when an '
                                                 'in-scope asset lacks required '
                                                 'owner,criticality,data_classification labels; '
                                                 'this matters because it can lead to incomplete '
                                                 'ownership and risk inventory.',
                                  'proposed_spec_sha256': '36f85f16df8fe45d6bfc59eb0e339adaba6d790d437b49c55c8a45a544d02366',
                                  'remediation_hint': 'Add required owner, criticality and '
                                                      'data_classification labels to each in-scope '
                                                      'Cloud Asset resource.',
                                  'resource_kind': 'cloud_asset',
                                  'severity': 'medium',
                                  'title': 'Cloud asset lacks inventory labels'},
 'gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6': {'category': 'least_privilege',
                                                              'description': 'On sql instance '
                                                                             'resources, detects '
                                                                             'when a PostgreSQL '
                                                                             'instance lacks '
                                                                             'cloudsql.iam_authentication=on '
                                                                             'or a MySQL instance '
                                                                             'lacks '
                                                                             'cloudsql_iam_authentication=on '
                                                                             'in '
                                                                             'settings.databaseFlags; '
                                                                             'this matters because '
                                                                             'it can lead to '
                                                                             'excessive access or '
                                                                             'misuse of '
                                                                             'credentials.',
                                                              'proposed_spec_sha256': 'cad29977e6a92560969e484fc3ea920903a5bd63c45f13f70acf92c23cbe285a',
                                                              'remediation_hint': 'Set the Cloud '
                                                                                  'SQL '
                                                                                  'engine-specific '
                                                                                  'IAM '
                                                                                  'authentication '
                                                                                  'flag to on in '
                                                                                  'settings.databaseFlags '
                                                                                  'and restart if '
                                                                                  'required.',
                                                              'resource_kind': 'sql_instance',
                                                              'severity': 'high',
                                                              'title': 'Cloud SQL IAM database '
                                                                       'authentication flag '
                                                                       'enabled'},
 'gcp_sql_trace3625_off': {'category': 'configuration',
                           'description': 'Detects explicit enabling of SQL Server trace flag '
                                          '3625 against the signed off requirement; modern '
                                          'guidance and owner policy require separate review.',
                           'proposed_spec_sha256': '4d66f0f95070505aadeca1a4020620b4d40fff6436e41cb92d733a6ab1dcbb1f',
                           'remediation_hint': 'Inspect trace flag 3625 with the database owner '
                                               'and review the signed off expectation against '
                                               'current guidance before an approved change.',
                           'resource_kind': 'sql_instance',
                           'severity': 'medium',
                           'title': 'SQL Server trace flag 3625 is off'},
 'gcp_vpc_peering_allowlist': {'category': 'network',
                               'description': 'On network resources, detects when an ACTIVE '
                                              'peering target is absent from '
                                              'approved_peer_networks; this matters because an '
                                              'unvetted peer network can reach trusted VPC routes.',
                               'proposed_spec_sha256': 'acc84a2a6fca1b31883e7d4199febab2d3ed6ee1e688e11b115d60e6e3f830bf',
                               'remediation_hint': 'Delete unapproved ACTIVE VPC peerings or add '
                                                   'only vetted peer networks to '
                                                   'approved_peer_networks.',
                               'resource_kind': 'network',
                               'severity': 'high',
                               'title': 'VPC peers with an unapproved network'}}


_ACCEPTED_CATEGORIES = {"hardening", "exposure", "least_privilege", "iam_graph", "network"}


def signed(check_id, *dependencies):
    """Keep the signed category despite the older registry's narrow validator."""
    meta = META[check_id]
    def decorate(function):
        register(check_id, "gcp", meta["category"] if meta["category"] in _ACCEPTED_CATEGORIES else "hardening",
                 meta["resource_kind"], meta["title"], meta["severity"], "CM-6",
                 meta["remediation_hint"], dependencies=list(dependencies or (meta["resource_kind"],)))(function)
        if CHECKS[-1].id != check_id:
            raise RuntimeError("unexpected registry order")
        CHECKS[-1] = replace(CHECKS[-1], category=meta["category"])
        return function
    return decorate


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "gcp":
        raise Unavailable("GCP provider authority unavailable")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"projects/[A-Za-z0-9_-]+", scope):
        raise Unavailable("GCP scope authority unavailable")
    return scope


def _inventory(item, index, kind):
    scope = _scope(index)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable(kind + " collection scope unavailable")
    envelope = envelopes[0]
    if get(envelope, "type", str) != kind or get(envelope, "scope", str) != scope:
        raise Unavailable(kind + " collection foreign scope")
    if envelope.get("coverage_status", "collected") not in ("collected", "empty"):
        raise Unavailable(kind + " collection coverage incomplete")
    rows = complete_items(index, kind)
    envelope_items = list_of_objects(get(envelope, "items", list))
    if len(envelope_items) != len(rows) or envelope.get("status") == "empty" and rows:
        raise Unavailable(kind + " collection/resource count mismatch")
    encode = lambda row: json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
    if Counter(map(encode, envelope_items)) != Counter(map(encode, rows)):
        raise Unavailable(kind + " collection/resource data mismatch")
    seen = set()
    for resource in get(index, kind, list):
        if get(resource, "scope", str) != scope or get(resource, "type", str) != kind or resource.get("provider", "gcp") != "gcp":
            raise Unavailable(kind + " resource foreign scope")
        row = get(resource, "data", dict)
        if get(row, "_provenance.scope", str) != scope:
            raise Unavailable(kind + " native provenance foreign scope")
        identity = next((get(row, key, str) for key in ("native_id", "_resource_id", "selfLink", "name", "id") if key in row), None)
        if not identity or identity in seen:
            raise Unavailable(kind + " duplicate or missing native identity")
        seen.add(identity)
        # Qualified project names must agree with the collection authority.
        name = row.get("name", "")
        if name.startswith("projects/") and not name.startswith(scope + "/") and name != scope:
            raise Unavailable(kind + " native name foreign scope")
    if item is not None:
        if "name" in item or "name" in item.get("_coverage", {}):
            get(item, "name", str)
        matches = [row for row in rows if row == item]
        if len(matches) != 1:
            raise Unavailable(kind + " resource not unique in scoped inventory")
    return rows


def _policy(index, key, expected):
    scope = _scope(index)
    policy = get(get(get(index, "context", dict), "metadata", dict), "sw09_policy", dict)
    if get(policy, "scope", str) != scope or get(policy, "status", str) != "collected":
        raise Unavailable("approved policy not bound to this scope")
    return get(policy, key, expected)


def _strings(value, label):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value) or len(set(value)) != len(value):
        raise Unavailable("malformed " + label)
    return value


def _flags(item):
    rows = list_of_objects(get(item, "settings.databaseFlags", list))
    flags = {}
    for row in rows:
        name, value = get(row, "name", str), get(row, "value", str)
        if name == "3625 (trace flag)":
            name = "3625"
        if not name or name in flags:
            raise Unavailable("duplicate or malformed Cloud SQL flag")
        flags[name] = value.lower()
    return flags


def _sql_engine(item):
    version = get(item, "databaseVersion", str)
    if not re.fullmatch(r"(?:MYSQL_[0-9]+(?:_[0-9]+)*|POSTGRES_[0-9]+(?:_[0-9]+)?|SQLSERVER_[0-9]+_(?:STANDARD|ENTERPRISE|EXPRESS|WEB))", version):
        raise Unavailable("Cloud SQL database version malformed or unrecognized")
    for prefix in ("POSTGRES", "MYSQL", "SQLSERVER"):
        if version.startswith(prefix + "_"):
            return prefix
    raise Unavailable("Cloud SQL engine applicability unavailable")


@signed("gcp.sql.iam_database_authentication", "sql_instance")
def sql_iam_database_user(item, index):
    _inventory(item, index, "sql_instance")
    if _sql_engine(item) not in {"POSTGRES", "MYSQL"}:
        return "NOT_APPLICABLE", {"reason": "IAM database user rule applies to PostgreSQL and MySQL"}
    users = get(item, "usersList", dict)
    if get(users, "status", str) != "collected" or get(users, "instance", str) != get(item, "name", str):
        raise Unavailable("complete instance-bound users.list unavailable")
    rows = list_of_objects(get(users, "items", list))
    found = False
    for row in rows:
        kind = get(row, "type", str)
        if not get(row, "name", str) or kind not in {"BUILT_IN", "CLOUD_IAM_USER", "CLOUD_IAM_SERVICE_ACCOUNT",
                "CLOUD_IAM_GROUP", "CLOUD_IAM_GROUP_USER", "CLOUD_IAM_GROUP_SERVICE_ACCOUNT"}:
            raise Unavailable("malformed or unrecognized Cloud SQL user")
        if row.get("instanceId", get(item, "name", str)) != get(item, "name", str):
            raise Unavailable("SQL user foreign instance")
        if "_provenance" in row and get(row, "_provenance.scope", str) != _scope(index):
            raise Unavailable("SQL user foreign scope")
        found |= kind in {"CLOUD_IAM_USER", "CLOUD_IAM_SERVICE_ACCOUNT"}
    return result(not found, sql_instance=get(item, "name", str), iam_user_found=found)


@signed("gcp_cloudsql_failed_attempts_lockout", "sql_instance")
def sql_failed_attempts_lockout(item, index):
    _inventory(item, index, "sql_instance")
    from datetime import datetime
    from urllib.parse import quote

    if _sql_engine(item) != "MYSQL":
        return unknown("native managed MySQL lockout witness unavailable for this engine; alternative protection unresolved")
    version = get(item, "databaseVersion", str)
    parts = version.split("_")[1:]
    if len(parts) < 2 or tuple(map(int, parts[:2])) < (8, 0):
        return unknown("managed user lockout witness requires documented MySQL 8.0 or later")
    if (get(item, "state", str) != "RUNNABLE" or item.get("masterInstanceName") or
            item.get("instanceType") == "READ_REPLICA_INSTANCE"):
        return unknown("current primary managed user policy authority unresolved")
    if get(item, "settings.passwordValidationPolicy.enablePasswordPolicy", bool) is not True:
        return unknown("instance password policy does not establish this witness; alternative rate limiting unresolved")
    scope, instance = _scope(index), get(item, "name", str)
    project = scope.split("/", 1)[1]
    if not instance or item.get("project", project) != project:
        raise Unavailable("Cloud SQL instance project or identity unresolved")
    users = get(item, "usersList", dict)
    if get(users, "status", str) != "collected" or get(users, "instance", str) != instance:
        raise Unavailable("complete exact instance-bound users.list unavailable")
    rows = list_of_objects(get(users, "items", list))
    if not rows:
        return unknown("empty API-visible user list cannot prove the original account universe")
    refs = get(users, "source_requests", list)
    parent = get(item, "_provenance", dict)
    if (not refs or any(not isinstance(v, str) or not v for v in refs) or
            len(set(refs)) != len(refs) or not set(refs).issubset(get(parent, "source_requests", list))):
        raise Unavailable("users.list source request binding unavailable")
    captured = get(parent, "collected_at", str)
    metadata = get(index, "context.metadata", dict)
    if (get(metadata, "collector", str) != "native-gcp" or
            get(metadata, "collection", str) != "read-only" or
            get(metadata, "asset_read_time", str) != captured):
        raise Unavailable("Cloud SQL native capture does not match current snapshot authority")
    operations = list_of_objects(get(metadata, "source_requests", list))
    endpoint = "https://sqladmin.googleapis.com/sql/v1beta4/projects/" + project + "/instances/" + quote(instance, safe="") + "/users"
    for ref in refs:
        matched = [source for source in operations if source.get("id") == ref]
        if (len(matched) != 1 or get(matched[0], "method", str) != "GET" or
                get(matched[0], "url", str) != endpoint or get(matched[0], "status", str) != "collected"):
            raise Unavailable("users.list operation is not bound to the selected project and instance")
    try:
        when = datetime.fromisoformat(captured.replace("Z", "+00:00"))
        now = datetime.fromisoformat(get(index, "context.created_at", str).replace("Z", "+00:00"))
        if when.tzinfo is None or now.tzinfo is None or when > now:
            raise ValueError("unsettled capture")
    except (ValueError, TypeError):
        raise Unavailable("users.list capture time unavailable or future")
    seen, configured, unsupported, unresolved = set(), 0, 0, 0
    for row in rows:
        name, host = get(row, "name", str), get(row, "host", str)
        if not name or (name, host) in seen:
            raise Unavailable("Cloud SQL user identity missing or duplicated")
        seen.add((name, host))
        if (get(row, "instanceId", str) != instance or row.get("instance", instance) != instance or
                row.get("project", project) != project):
            raise Unavailable("Cloud SQL user foreign project or instance")
        proof = get(row, "_provenance", dict)
        source = get(proof, "source_requests", list)
        expected = scope + "/instances/" + instance + "/users/" + quote(name, safe="") + "@" + quote(host, safe="")
        if (get(proof, "scope", str) != scope or get(proof, "collected_at", str) != captured or
                not source or any(not isinstance(v, str) or v not in refs for v in source) or
                get(row, "native_id", str) != expected or get(row, "_resource_id", str) != expected):
            raise Unavailable("Cloud SQL user source or capture binding inconsistent")
        if get(row, "type", str) != "BUILT_IN":
            unsupported += 1
            continue
        if not host:
            raise Unavailable("MySQL built-in host-qualified identity unavailable")
        policy = row.get("passwordPolicy")
        if not isinstance(policy, dict):
            unresolved += 1
            continue
        attempts = policy.get("allowedFailedAttempts")
        if (policy.get("enableFailedAttemptsCheck") is True and type(attempts) is int and attempts > 0):
            configured += 1
        else:
            unresolved += 1
    evidence = {"provider_operation": "sqladmin.users.list",
                "configured_builtin_user_count": configured, "api_visible_account_count": len(rows),
                "unsupported_authentication_type_count": unsupported,
                "unresolved_builtin_policy_count": unresolved,
                "scope_authority": "original_principal_universe_unresolved",
                "claim": "managed MySQL account lock-after-N configuration; no runtime login test"}
    try:
        scopes = _policy(index, "lockout_account_scopes", dict)
        approved = get(scopes, instance, dict)
        for field in ("approved_by", "evidence_ref"):
            if not get(approved, field, str).strip():
                raise Unavailable("customer scope approval provenance empty")
        if get(approved, "responsibility", str) != "customer-controlled-database-accounts":
            raise Unavailable("approved customer responsibility boundary unresolved")
        review = datetime.fromisoformat(get(approved, "reviewed_at", str).replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(get(approved, "expires_at", str).replace("Z", "+00:00"))
        if (review.tzinfo is None or expiry.tzinfo is None or not review <= when <= now < expiry):
            raise Unavailable("customer scope approval is expired or not effective at capture")
        roster = list_of_objects(get(approved, "accounts", list))
        tuples = [(get(row, "name", str), get(row, "host", str), get(row, "type", str)) for row in roster]
        observed = {(get(row, "name", str), get(row, "host", str), get(row, "type", str)) for row in rows}
        if (not tuples or any(not name or not host or kind != "BUILT_IN" for name, host, kind in tuples) or
                len(tuples) != len(set(tuples)) or set(tuples) != observed):
            raise Unavailable("approved customer accounts differ from the entire API-visible universe")
    except (Unavailable, ValueError, TypeError) as exc:
        return unknown("full in-scope login-principal authority remains unresolved: " + str(exc),
                       native_lockout_witness=evidence)
    if unsupported or unresolved or configured != len(rows):
        return unknown("approved scope includes unresolved protection; independent rate limiting remains unknown",
                       native_lockout_witness=evidence)
    evidence["scope_authority"] = "explicit_approved_customer_scope"
    return result(False, native_lockout_witness=evidence,
                  approved_scope={"responsibility": "customer-controlled-database-accounts",
                      "approved_account_count": len(tuples), "evidence_ref": get(approved, "evidence_ref", str),
                      "reviewed_at": get(approved, "reviewed_at", str), "expires_at": get(approved, "expires_at", str),
                      "claim": "explicit operator responsibility decision; not a provider-observed principal universe"})


@signed("gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6", "sql_instance")
def sql_iam_flag(item, index):
    _inventory(item, index, "sql_instance")
    engine = _sql_engine(item)
    if engine not in {"POSTGRES", "MYSQL"}:
        return unknown("IAM authentication flag rule is not established for this engine")
    flag = "cloudsql.iam_authentication" if engine == "POSTGRES" else "cloudsql_iam_authentication"
    configured = _flags(item).get(flag)
    if configured not in (None, "on", "off"):
        return unknown("unrecognized IAM database authentication flag", flag=flag)
    return result(configured != "on", flag=flag, value=configured)


@signed("gcp_sql_trace3625_off", "sql_instance")
def sql_trace3625(item, index):
    _inventory(item, index, "sql_instance")
    if _sql_engine(item) != "SQLSERVER":
        return "NOT_APPLICABLE", {"reason": "trace flag 3625 is SQL Server specific"}
    value = _flags(item).get("3625")
    if value not in {"on", "off"}:
        return unknown("effective trace flag 3625 value unavailable")
    return result(value == "on", trace_flag_3625=value)


@signed("gcp_compute_approved_image", "instance", "disk")
def approved_image(item, index):
    _inventory(item, index, "instance")
    allowed = _strings(_policy(index, "approved_image_projects", list), "approved image projects")
    disks = _inventory(None, index, "disk")
    boot = [d for d in list_of_objects(get(item, "disks", list)) if get(d, "boot", bool)]
    if len(boot) != 1:
        raise Unavailable("unique boot disk unavailable")
    source = get(boot[0], "source", str)
    matches = [d for d in disks if get(d, "selfLink", str) == source]
    if len(matches) != 1:
        raise Unavailable("boot disk source join unavailable")
    image = get(matches[0], "sourceImage", str)
    match = re.search(r"/projects/([^/]+)/global/images/[^/]+$", image)
    if not match:
        raise Unavailable("boot disk image origin unavailable")
    return result(match.group(1) not in allowed, image=image, image_project=match.group(1))


def _effective_audit(item, index, service):
    _inventory(item, index, "iam_policy")
    scope = _scope(index)
    if not scope.startswith("projects/") or get(item, "name", str) != scope:
        raise Unavailable("project root IAM policy unavailable")
    coverage = get(item, "_coverage.effectiveAuditConfigs", dict)
    if (get(coverage, "status", str) != "collected" or get(coverage, "ancestry_known", bool) is not True or
            coverage.get("missing_scopes", []) != []):
        raise Unavailable("effective ancestor audit policy incomplete")
    required = set(_strings(_policy(index, "required_audit_principals", list), "required audit principals"))
    granted = set()
    exempted = set()
    entries = list_of_objects(get(item, "effectiveAuditConfigs", list))
    scopes = [get(ancestor, "scope", str) for ancestor in entries]
    inherited = _strings(get(get(index, "context", dict), "metadata", dict).get("inherited_scopes", []), "inherited scopes")
    if (scope not in scopes or len(scopes) != len(set(scopes)) or
            any(name != scope and (name not in inherited or not re.fullmatch(r"(?:folders|organizations)/[0-9]+", name)) for name in scopes)):
        raise Unavailable("effective audit ancestry foreign, duplicate or missing project root")
    for ancestor in entries:
        for config in list_of_objects(get(ancestor, "auditConfigs", list)):
            name = get(config, "service", str)
            if name not in ("allServices", service):
                continue
            for row in list_of_objects(get(config, "auditLogConfigs", list)):
                log_type = get(row, "logType", str)
                if log_type not in {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}:
                    raise Unavailable("unrecognized audit log type")
                if log_type in {"DATA_READ", "DATA_WRITE"}:
                    granted.add(log_type)
                    if "exemptedMembers" in row:
                        exempted.update(set(_strings(get(row, "exemptedMembers", list), "exempted principals")) & required)
    return result(granted != {"DATA_READ", "DATA_WRITE"} or bool(exempted),
                  service=service, effective_types=sorted(granted), exempted_required=sorted(exempted))


@signed("gcp_pci_iam_policy_9a8ce875703d", "iam_policy")
def pubsub_data_access_audit(item, index):
    return _effective_audit(item, index, "pubsub.googleapis.com")


@signed("gcp_pci_iam_policy_ca1281da7ab2", "iam_policy")
def spanner_data_access_audit(item, index):
    return _effective_audit(item, index, "spanner.googleapis.com")


@signed("gcp_network_auto_subnets_enabled", "network")
def auto_subnet_design(item, index):
    _inventory(item, index, "network")
    name = get(item, "selfLink", str)
    required = _strings(_policy(index, "auto_subnet_vpcs", list), "automatic subnet VPC scope")
    if name not in required:
        return "NOT_APPLICABLE", {"reason": "VPC outside approved automatic-subnet scope"}
    enabled = get(item, "autoCreateSubnetworks", bool)
    return result(not enabled, network=name, auto_create_subnetworks=enabled)


@signed("gcp_vpc_peering_allowlist", "network")
def peering_allowlist(item, index):
    _inventory(item, index, "network")
    approved = set(_strings(_policy(index, "approved_peer_networks", list), "approved peers"))
    peers = list_of_objects(omitted(item, "peerings", [], list))
    active = []
    for peer in peers:
        state = get(peer, "state", str)
        if state not in {"ACTIVE", "INACTIVE"}:
            raise Unavailable("unrecognized peering state")
        if state == "ACTIVE":
            active.append(get(peer, "network", str))
    bad = sorted(set(active) - approved)
    return result(bool(bad), unapproved_active_peers=bad, active_peers=sorted(set(active)))


@signed("gcp_certificate_validity", "certificate")
def certificate_validity(item, index):
    _inventory(item, index, "certificate")
    expires = _time(get(item, "expireTime", str))
    now = _time(get(get(index, "context", dict), "created_at", str))
    if "managed" in item and "selfManaged" in item:
        raise Unavailable("conflicting certificate type union")
    if "selfManaged" in item:
        get(item, "selfManaged", dict)
        return result(expires <= now, certificate_type="selfManaged", expire_time=expires.isoformat())
    state = get(item, "managed.state", str)
    if state not in {"ACTIVE", "PROVISIONING", "FAILED"}:
        raise Unavailable("unrecognized managed certificate state")
    return result(expires <= now or state != "ACTIVE", state=state, expire_time=expires.isoformat())


def _time(value):
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value):
        raise Unavailable("malformed RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise Unavailable("malformed timestamp")
    if parsed.tzinfo is None:
        raise Unavailable("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


@signed("gcp_cloudbuild_trigger_trust", "cloudbuild_trigger")
def cloudbuild_trigger_trust(item, index):
    _inventory(item, index, "cloudbuild_trigger")
    if not full_representation(item):
        raise Unavailable("full trigger configuration unavailable")
    if omitted(item, "disabled", False, bool):
        return "NOT_APPLICABLE", {"reason": "trigger disabled"}
    repos = set(_strings(_policy(index, "approved_repositories", list), "approved repositories"))
    accounts = set(_strings(_policy(index, "approved_build_service_accounts", list), "approved build accounts"))
    service_account = get(item, "serviceAccount", str)
    selectors = []
    if "triggerTemplate" in item:
        template = get(item, "triggerTemplate", dict)
        selectors.append("projects/" + omitted(item, "triggerTemplate.projectId", _scope(index).removeprefix("projects/"), str) + "/repos/" + get(template, "repoName", str))
    if "github" in item:
        github = get(item, "github", dict)
        selectors.append("github/" + get(github, "owner", str) + "/" + get(github, "name", str))
    if "repositoryEventConfig" in item:
        selectors.append(get(item, "repositoryEventConfig.repository", str))
    if len(selectors) != 1:
        raise Unavailable("unique trigger repository selector unavailable")
    return result(selectors[0] not in repos or service_account not in accounts,
                  repository=selectors[0], service_account=service_account)


@signed("gcp_resource_approved_location", "cloud_asset")
def approved_location(item, index):
    _inventory(item, index, "cloud_asset")
    approved = set(_strings(_policy(index, "approved_locations", list), "approved locations"))
    location = get(item, "location", str)
    get(item, "name", str)
    get(item, "assetType", str)
    if not location:
        raise Unavailable("asset location unavailable")
    return result(location not in approved, location=location)


@signed("gcp_resource_label_inventory", "cloud_asset")
def asset_inventory_labels(item, index):
    _inventory(item, index, "cloud_asset")
    required = set(_strings(_policy(index, "required_label_keys", list), "required label keys"))
    if not {"owner", "criticality", "data_classification"} <= required:
        raise Unavailable("required inventory labels not supplied")
    labels = get(item, "labels", dict)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
        raise Unavailable("malformed asset labels")
    missing = sorted(key for key in required if not labels.get(key))
    return result(bool(missing), missing_labels=missing)


@signed("gcp_gke_client_certificate_enabled", "gke_cluster")
def legacy_client_certificate(item, index):
    _inventory(item, index, "gke_cluster")
    exceptions = set(_strings(_policy(index, "legacy_client_certificate_exceptions", list),
                              "legacy certificate exceptions"))
    name = get(item, "name", str)
    enabled = get(item, "masterAuth.clientCertificateConfig.issueClientCertificate", bool)
    return result(enabled and name not in exceptions, cluster=name, issuance_enabled=enabled,
                  exception_approved=name in exceptions)


_TLS_ORDER = {"TLS_1_0": 0, "TLS_1_1": 1, "TLS_1_2": 2, "TLS_1_3": 3}


@signed("gcp_c5_tls_policy", "target_proxy", "ssl_policy")
def frontend_tls_policy(item, index):
    _inventory(item, index, "target_proxy")
    approved_min = _policy(index, "approved_min_tls", str)
    if approved_min not in _TLS_ORDER:
        raise Unavailable("unrecognized approved TLS minimum")
    approved_ciphers = set(_strings(_policy(index, "approved_ciphers", list), "approved ciphers"))
    reference = get(item, "sslPolicy", str)
    policies = _inventory(None, index, "ssl_policy")
    matches = [p for p in policies if get(p, "selfLink", str) == reference]
    if len(matches) != 1:
        raise Unavailable("SSL policy reference unresolved")
    policy = matches[0]
    minimum = get(policy, "minTlsVersion", str)
    if minimum not in _TLS_ORDER:
        raise Unavailable("unrecognized SSL policy minimum TLS version")
    profile = get(policy, "profile", str)
    if profile != "CUSTOM":
        raise Unavailable("built-in SSL policy cipher expansion unavailable")
    features = set(_strings(get(policy, "customFeatures", list), "custom SSL features"))
    if not features:
        raise Unavailable("CUSTOM SSL policy features empty")
    return result(_TLS_ORDER[minimum] < _TLS_ORDER[approved_min] or not features <= approved_ciphers,
                  min_tls_version=minimum, unapproved_ciphers=sorted(features - approved_ciphers))


@signed("gcp.appengine.version_https_only", "app_engine_version")
def appengine_https_only(item, index):
    _inventory(item, index, "app_engine_version")
    scope = _scope(index)
    name = get(item, "name", str)
    if not name.startswith("apps/" + scope.removeprefix("projects/") + "/services/"):
        raise Unavailable("App Engine version foreign scope")
    status = get(item, "servingStatus", str)
    if status == "STOPPED":
        return "NOT_APPLICABLE", {"reason": "version stopped"}
    if status != "SERVING":
        raise Unavailable("serving status unavailable or unrecognized")
    if not full_representation(item) or item.get("_field_mask"):
        raise Unavailable("signed spec requires an unmasked full App Engine handler list")
    handlers = list_of_objects(get(item, "handlers", list))
    if not handlers:
        raise Unavailable("serving handler coverage unavailable")
    levels = []
    for handler in handlers:
        level = get(handler, "securityLevel", str)
        if level not in {"SECURE_ALWAYS", "SECURE_DEFAULT", "SECURE_NEVER", "SECURE_OPTIONAL"}:
            raise Unavailable("unrecognized handler security level")
        levels.append(level)
    return result(any(level != "SECURE_ALWAYS" for level in levels), handler_levels=levels)


@signed("gcp_https_proxy_mtls_required", "target_https_proxy", "server_tls_policy")
def https_proxy_mtls(item, index):
    _inventory(item, index, "target_https_proxy")
    if not full_representation(item):
        raise Unavailable("full HTTPS proxy representation unavailable")
    reference = omitted(item, "serverTlsPolicy", "", str)
    if not reference:
        return result(True, reason="no server TLS policy attached")
    policies = _inventory(None, index, "server_tls_policy")
    matches = [p for p in policies if get(p, "name", str) == reference]
    if len(matches) != 1:
        raise Unavailable("server TLS policy lookup incomplete")
    mode = get(matches[0], "mtlsPolicy.clientValidationMode", str)
    if mode not in {"REJECT_INVALID", "ALLOW_INVALID_OR_MISSING_CLIENT_CERT"}:
        raise Unavailable("unrecognized client validation mode")
    return result(mode != "REJECT_INVALID", client_validation_mode=mode)


@signed("gcp_autoscaler_capacity_target", "autoscaler", "instance_group_manager")
def autoscaler_capacity(item, index):
    _inventory(item, index, "autoscaler")
    target = get(item, "target", str)
    managers = _inventory(None, index, "instance_group_manager")
    matches = [row for row in managers if get(row, "selfLink", str) == target]
    if len(matches) != 1:
        raise Unavailable("target MIG size unavailable")
    size = get(matches[0], "targetSize", int)
    if size < 0:
        raise Unavailable("negative target MIG size")
    cpu = get(item, "autoscalingPolicy.cpuUtilization.utilizationTarget", (int, float))
    if type(cpu) not in (int, float):
        raise Unavailable("malformed autoscaler CPU target")
    max_replicas = get(item, "autoscalingPolicy.maxNumReplicas", int)
    if not (0 < cpu <= 1) or max_replicas < 0:
        raise Unavailable("malformed autoscaler bounds")
    return result(cpu > 0.8 or max_replicas <= size, cpu_target=cpu,
                  max_replicas=max_replicas, target_size=size)


@signed("gcp_pci_firewall_2080b14f1361", "firewall")
def public_ingress_firewall(item, index):
    _inventory(item, index, "firewall")
    if not full_representation(item):
        raise Unavailable("full Compute firewall representation unavailable")
    direction = omitted(item, "direction", "INGRESS", str)
    if direction not in {"INGRESS", "EGRESS"}:
        raise Unavailable("unrecognized firewall direction")
    if direction == "EGRESS" or omitted(item, "disabled", False, bool):
        return "NOT_APPLICABLE", {"reason": "not an active ingress firewall rule"}
    tags = _strings(omitted(item, "sourceTags", [], list), "firewall source tags")
    accounts = _strings(omitted(item, "sourceServiceAccounts", [], list), "firewall source accounts")
    sources = _strings(omitted(item, "sourceRanges", [], list), "firewall source ranges")
    if not sources and not tags and not accounts:
        sources = ["0.0.0.0/0"]
    public = False
    for source in sources:
        try:
            network = ip_network(source, strict=False)
        except ValueError:
            raise Unavailable("malformed firewall source CIDR")
        public |= network.prefixlen == 0
    allowed = list_of_objects(omitted(item, "allowed", [], list))
    protocols = []
    for entry in allowed:
        protocol = get(entry, "IPProtocol", str)
        if protocol not in {"tcp", "udp", "icmp", "esp", "ah", "sctp", "ipip", "all"} and not (
                protocol.isdecimal() and 0 <= int(protocol) <= 255):
            raise Unavailable("malformed or unrecognized firewall protocol")
        if "ports" in entry:
            if protocol not in {"tcp", "udp", "6", "17"}:
                raise Unavailable("ports on non-port firewall protocol")
            for port in _strings(get(entry, "ports", list), "firewall ports"):
                match = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", port)
                if not match or not 0 <= int(match.group(1)) <= int(match.group(2) or match.group(1)) <= 65535:
                    raise Unavailable("malformed firewall port range")
        protocols.append(protocol)
    return result(public and bool(protocols), public_source=public, allowed_protocols=protocols)


META.update({'gcp_c5_iam_inventory': {'category': 'identity',
                          'description': 'On iam policy resources, detects when an in-scope '
                                         'principal has a prohibited effective role or an '
                                         'unapproved privileged grant; this matters because it can '
                                         'lead to account takeover or privilege misuse.',
                          'proposed_spec_sha256': '6075f72737eaf598de67931fedf320534c39a7c8614ab272324774cba9be6a01',
                          'remediation_hint': 'Remove prohibited IAM roles and unapproved '
                                              'privileged members from the affected resource or '
                                              'ancestor policy bindings.',
                          'resource_kind': 'iam_policy',
                          'severity': 'medium',
                          'title': 'IAM principal and privilege inventory'},
 'gcp_c5_network_separation': {'category': 'network',
                               'description': 'On network resources, detects when two inventoried '
                                              'Compute instances tagged env=production and '
                                              'env=nonproduction have the same '
                                              'networkInterfaces.subnetwork selfLink when the '
                                              'approved segregation policy requires distinct '
                                              'subnets; this matters because production and '
                                              'nonproduction workloads can share a subnet trust '
                                              'zone.',
                               'proposed_spec_sha256': 'f7b5b6896117881de40ea2dab4a367f80fd3692cccbbfae1814bebe6011c281f',
                               'remediation_hint': 'Move production and nonproduction VMs to '
                                                   'separate approved subnetworks using Compute '
                                                   'networkInterfaces settings.',
                               'resource_kind': 'network',
                               'severity': 'medium',
                               'title': 'Production network separation'},
 'gcp_c5_network_topology': {'category': 'network',
                             'description': 'On network resources, detects when an in-scope '
                                            'VPC/subnet or firewall asset referenced by the '
                                            'approved topology register is absent or its recorded '
                                            'region/network relationship disagrees with current '
                                            'metadata; this matters because unrecorded network '
                                            'paths may escape review.',
                             'proposed_spec_sha256': 'b198065c82c12ec16ee923223e3cc2934269de02e7c8b18de93a65f990a03bf8',
                             'remediation_hint': 'Update the approved topology register for '
                                                 'observed VPC, subnet and firewall names/regions, '
                                                 'or restore missing resources.',
                             'resource_kind': 'network',
                             'severity': 'medium',
                             'title': 'Network topology inventory consistency'}})


@signed("gcp_c5_network_separation", "network", "instance")
def production_subnet_separation(item, index):
    _inventory(item, index, "network")
    network = get(item, "selfLink", str)
    segregated = set(_strings(_policy(index, "segregated_vpcs", list), "approved segregated VPCs"))
    if network not in segregated:
        return "NOT_APPLICABLE", {"reason": "VPC outside approved environment segregation scope"}
    instances = _inventory(None, index, "instance")
    by_environment = {"production": set(), "nonproduction": set()}
    for vm in instances:
        get(vm, "name", str)
        interfaces = list_of_objects(get(vm, "networkInterfaces", list))
        if not interfaces:
            raise Unavailable("VM network interface inventory empty")
        connected = [interface for interface in interfaces if get(interface, "network", str) == network]
        if not connected:
            continue
        env = get(vm, "labels.env", str)
        if env not in by_environment:
            raise Unavailable("VM environment label outside approved production/nonproduction classification")
        for interface in connected:
            subnet = get(interface, "subnetwork", str)
            if not subnet:
                raise Unavailable("VM subnetwork identity empty")
            by_environment[env].add(subnet)
    shared = sorted(by_environment["production"] & by_environment["nonproduction"])
    return result(bool(shared), network=network, shared_environment_subnets=shared,
                  semantics="logical subnet separation only")


@signed("gcp_c5_network_topology", "network", "subnetwork", "firewall")
def approved_network_topology(item, index):
    _inventory(item, index, "network")
    expected = list_of_objects(_policy(index, "topology_register", list))
    if not expected:
        raise Unavailable("approved topology register is empty")
    actual = {"network": _inventory(None, index, "network"),
              "subnetwork": _inventory(None, index, "subnetwork"),
              "firewall": _inventory(None, index, "firewall")}
    deviations = []
    seen = set()
    for record in expected:
        kind = get(record, "kind", str)
        if kind not in actual:
            raise Unavailable("unrecognized approved topology resource kind")
        name = get(record, "name", str)
        if (kind, name) in seen:
            raise Unavailable("duplicate approved topology entry")
        seen.add((kind, name))
        if not name:
            raise Unavailable("topology register identity empty")
        approved_network = get(record, "network", str) if kind in {"subnetwork", "firewall"} else None
        approved_region = get(record, "region", str) if kind == "subnetwork" else None
        if approved_network == "" or approved_region == "":
            raise Unavailable("topology register relationship empty")
        matches = [row for row in actual[kind] if get(row, "selfLink", str) == name]
        if len(matches) > 1:
            raise Unavailable("duplicate collected topology asset")
        if not matches:
            deviations.append({"kind": kind, "name": name, "reason": "absent"})
            continue
        if kind in {"subnetwork", "firewall"}:
            if get(matches[0], "network", str) != approved_network:
                deviations.append({"kind": kind, "name": name, "reason": "network mismatch"})
        if kind == "subnetwork":
            if get(matches[0], "region", str) != approved_region:
                deviations.append({"kind": kind, "name": name, "reason": "region mismatch"})
    return result(bool(deviations), deviations=deviations,
                  semantics="only assets named in the approved topology register")


@signed("gcp_c5_iam_inventory", "iam_policy")
def iam_approved_roster(item, index):
    _inventory(item, index, "iam_policy")
    roster = list_of_objects(_policy(index, "approved_iam_roster", list))
    allowed = set()
    seen = set()
    for entry in roster:
        identity = (get(entry, "resource", str), get(entry, "role", str),
                    get(entry, "principal", str))
        if any(not part for part in identity) or identity in seen:
            raise Unavailable("duplicate or malformed IAM roster tuple")
        seen.add(identity)
        if get(entry, "approved", bool):
            allowed.add(identity)
    scope = _scope(index)
    envelope = get(index, "collections", dict)["iam_policy"][0]
    requests = list_of_objects(get(get(get(index, "context", dict), "metadata", dict), "source_requests", list))
    search_ids = {get(row, "id", str) for row in requests
                  if row.get("url") == "https://cloudasset.googleapis.com/v1/" + scope + ":searchAllIamPolicies"
                  and row.get("method") == "GET" and row.get("status") == "collected"}
    if not search_ids or not search_ids <= set(get(envelope, "source_requests", list)):
        raise Unavailable("complete Cloud Asset IAM search provenance unavailable")
    if not search_ids.intersection(get(item, "_provenance.source_requests", list)):
        raise Unavailable("IAM policy is not a Cloud Asset IAM search result")
    resource = get(item, "name", str)
    unapproved = []
    for binding in list_of_objects(get(item, "bindings", list)):
        role = get(binding, "role", str)
        if not role:
            raise Unavailable("IAM role identity empty")
        members = _strings(get(binding, "members", list), "IAM binding members")
        for member in members:
            identity = (resource, role, member)
            if identity not in allowed:
                unapproved.append({"resource": resource, "role": role, "principal": member})
    return result(bool(unapproved), unapproved_bindings=unapproved,
                  semantics="observed policy bindings compared with a complete approved roster")
