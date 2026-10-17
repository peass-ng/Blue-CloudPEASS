"""Native declaration predicates with explicit dependency and entity scope."""
from datetime import timedelta
from . import register, result, unknown
from .facts import get, optional, complete_items, unique_join, list_of_objects, Unavailable, omitted
from .fixtures import CASES
from .gcp_ports_keys import parse_time

IDS, REFERENCE_SPECS = [], {}


def rule(query, kind, function, good, bad, dependencies=None, title=None):
    cid = "gcp.ports." + query
    IDS.append(cid)
    register(cid, "gcp", "hardening", kind, title or query.replace("_", " "), "medium", "CM-6",
        "Review the collected declaration and its scope; effective authorization and runtime enforcement need separate evidence.",
        dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


def dns(query, key_type=None):
    def evaluate(item, index):
        visibility = get(item, "visibility", str)
        if visibility == "private":
            return "NOT_APPLICABLE", {"reason": "DNSSEC source control excludes private zones"}
        if visibility != "public":
            return unknown("unrecognized DNS visibility")
        config = optional(item, "dnssecConfig", {}, dict)
        state = optional(config, "state", None, str)
        if state not in (None, "on", "off", "transfer"):
            return unknown("unrecognized DNSSEC state")
        if key_type is None:
            return result(state in (None, "off"), state=state,
                semantics="Declared source non-off configuration; transfer is not active signing proof")
        specs = list_of_objects(optional(config, "defaultKeySpecs", [], list))
        weak = [spec for spec in specs if get(spec, "keyType", str) == key_type and get(spec, "algorithm", str) == "rsasha1"]
        return result(state is None or bool(weak), key_type=key_type, state=state,
            semantics="Algorithm declaration only; DNSSEC enablement is a separate check")
    config = {"visibility": "public", "dnssecConfig": {"state": "on"}}
    bad = {"visibility": "public", "dnssecConfig": {"state": "off"}}
    if key_type:
        bad = {"visibility": "public", "dnssecConfig": {"state": "on", "defaultKeySpecs": [{"keyType": key_type, "algorithm": "rsasha1"}]}}
    rule(query, "dns_managed_zone", evaluate, config, bad)


dns("dns_managed_zone_dnssec_enabled")
dns("dns_managed_zone_key_signing_not_using_rsasha1", "keySigning")
dns("dns_managed_zone_zone_signing_not_using_rsasha1", "zoneSigning")


def policy_public(query, kind, invoker_only=False, active_only=False):
    if query == "kms_key_not_publicly_accessible":
        cid = "gcp.reviewed.kms.no_public_iam"
        IDS.append(cid)
        REFERENCE_SPECS[query] = cid
        return
    def evaluate(item, index):
        if active_only and get(item, "state", str) != "ACTIVE":
            return "NOT_APPLICABLE", {"reason": "Source excludes transient function states"}
        bindings = list_of_objects(get(item, "iamPolicy.bindings", list))
        public = []
        for binding in bindings:
            role = get(binding, "role", str)
            members = get(binding, "members", list)
            if any(not isinstance(member, str) for member in members):
                raise Unavailable("malformed IAM member declaration")
            if invoker_only and role != "roles/run.invoker":
                continue
            if {"allUsers", "allAuthenticatedUsers"}.intersection(members):
                public.append({"role": role, "condition": optional(binding, "condition", None, dict)})
        return result(bool(public), public_bindings=public,
            semantics="Public principal binding declaration; conditions, deny and PAB are not flattened into effective access")
    good = {"iamPolicy": {"bindings": []}}
    bad = {"iamPolicy": {"bindings": [{"role": "roles/run.invoker" if invoker_only else "roles/viewer", "members": ["allUsers"]}]}}
    if active_only:
        good["state"] = bad["state"] = "ACTIVE"
    rule(query, kind, evaluate, good, bad)


policy_public("storage_bucket_not_publicly_accessible", "bucket")
policy_public("kms_key_not_publicly_accessible", "kms_key")
policy_public("cloudfunction_function_restrict_public_access", "function")
policy_public("function_active_public_binding", "function", active_only=True)
policy_public("cloudrun_service_restrict_public_access", "cloudrun_service", invoker_only=True)


def dataset_public(item, index):
    # datasets.get omits an empty ACL; absent is [] only on a full representation.
    access = list_of_objects(omitted(item, "access", [], list))
    return result(any(row.get("specialGroup") == "allAuthenticatedUsers" or row.get("iamMember") == "allUsers" for row in access),
        semantics="Dataset public ACL declarations; authorized views and effective permissions are separate")


rule("bigquery_dataset_not_publicly_accessible", "bigquery_dataset", dataset_public,
    {"access": []}, {"access": [{"specialGroup": "allAuthenticatedUsers"}]})


def function_setting(query, field, active_only=False):
    def evaluate(item, index):
        if active_only and get(item, "state", str) != "ACTIVE":
            return "NOT_APPLICABLE", {"reason": "Function is not ACTIVE"}
        config = get(item, "serviceConfig", dict)
        value = optional(config, field, "", str)
        return result(value == "ALLOW_ALL" if field == "ingressSettings" else not value,
            configured=value, semantics="Ingress/connector configuration, not permission or egress-route proof")
    good = {"serviceConfig": {field: "ALLOW_INTERNAL_ONLY" if field == "ingressSettings" else "projects/p/locations/r/connectors/c"}}
    bad = {"serviceConfig": {field: "ALLOW_ALL" if field == "ingressSettings" else ""}}
    if active_only:
        good["state"] = bad["state"] = "ACTIVE"
    rule(query, "function", evaluate, good, bad)


function_setting("cloudfunction_function_no_ingress_settings_allow_all", "ingressSettings")
function_setting("cloudfunction_function_vpc_connector_enabled", "vpcConnector")
function_setting("function_active_vpc_connector", "vpcConnector", True)


def sql_address(query, criterion):
    def evaluate(item, index):
        addresses = list_of_objects(get(item, "ipAddresses", list))
        types = [get(address, "type", str) for address in addresses]
        if any(value not in ("PRIMARY", "PRIVATE", "OUTGOING", "MIGRATED_1ST_GEN") for value in types):
            return unknown("unrecognized SQL address type")
        if criterion == "private_only":
            public_incoming = [value for value in types if value in ("PRIMARY", "MIGRATED_1ST_GEN")]
            return result(bool(public_incoming), address_types=types, public_incoming_types=public_incoming,
                private_incoming_present="PRIVATE" in types, outgoing_source_present="OUTGOING" in types,
                semantics="No observed public incoming SQL IP in the collected address declarations; OUTGOING is an outbound source and does not prove a private incoming endpoint or effective reachability")
        # The other pinned source variants did not assess migrated V1 addresses.
        # Do not silently mark one safe when PRIMARY is absent.
        if "MIGRATED_1ST_GEN" in types and "PRIMARY" not in types:
            return unknown("legacy migrated SQL IP not assessed by this source variant")
        if criterion == "source_second_gen":
            failed = "PRIMARY" in types and get(item, "backendType", str) == "SECOND_GEN"
        elif criterion == "private_network":
            config = get(item, "settings.ipConfiguration", dict)
            failed = "PRIVATE" not in types or "PRIMARY" in types or not optional(config, "privateNetwork", "", str)
        else:
            failed = "PRIMARY" in types
        return result(failed, address_types=types, semantics="Address declarations only, not network reachability")
    good = {"ipAddresses": [{"type": "PRIVATE"}], "backendType": "SECOND_GEN", "settings": {"ipConfiguration": {"privateNetwork": "projects/p/global/networks/v"}}}
    bad = {**good, "ipAddresses": [{"type": "PRIMARY"}]}
    rule(query, "sql_instance", evaluate, good, bad,
         title="Cloud SQL instance has no observed public incoming IP address" if criterion == "private_only" else None)


sql_address("sql_instance_with_no_public_ips", "source_second_gen")
sql_address("sql_instance_not_publicly_accessible", "private_network")
sql_address("sql_private_ip_assignments", "private_only")
sql_address("sql_no_primary_address", "primary")


def project_no_keys(item, index):
    project = get(item, "projectId", str)
    keys = complete_items(index, "api_key")
    matches = [get(key, "name", str) for key in keys if get(key, "name", str).startswith("projects/" + project + "/")]
    # Project-number key names cannot safely join a project-ID without its native number.
    number = optional(item, "name", "", str).removeprefix("projects/")
    if number and number != project:
        matches += [get(key, "name", str) for key in keys if get(key, "name", str).startswith("projects/" + number + "/")]
    return result(bool(matches), key_metadata_names=matches, semantics="Complete scoped API key inventory, no key strings")


cid = rule("project_no_api_key", "project", project_no_keys, {"projectId": "p"}, {"projectId": "q"}, ["project", "api_key"])
CASES[cid]["index"] = {"collections": {"api_key": [{"status": "collected"}]}, "api_key": [{"data": {"name": "projects/q/locations/global/keys/k"}}]}


def elapsed_age(item, index):
    captured = parse_time(item.get("_provenance", {}).get("collected_at") or index.get("context", {}).get("created_at"))
    created = parse_time(get(item, "createTime", str))
    return result((captured - created).days > 90, created_at=created.isoformat(), captured_at=captured.isoformat(),
        semantics="Pinned Prowler elapsed whole-day >90 cutoff at immutable captured clock")


rule("api_key_elapsed_age_gt90", "api_key", elapsed_age,
    {"createTime": "2026-10-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}},
    {"createTime": "2026-01-01T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}})
