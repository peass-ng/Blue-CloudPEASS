"""Source-specific default/configuration predicates; no runtime defaults invented."""
from . import register, result, unknown
from .facts import get, optional, complete_items, list_of_objects, Unavailable
from .fixtures import CASES

IDS, REFERENCE_SPECS, SQL_SPECS = [], {}, {}


def rule(query, kind, function, good, bad, dependencies=None):
    cid = "gcp.ports." + query
    IDS.append(cid)
    register(cid, "gcp", "hardening", kind, query.replace("_", " "), "medium", "CM-6",
        "Review the source-specific native configuration and documented omission defaults for the actual service/version.",
        dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


def sql(query, engine, flag, default, allowed, bad):
    def evaluate(item, index):
        version = get(item, "databaseVersion", str)
        if not version.startswith(("MYSQL", "POSTGRES", "SQLSERVER")):
            return unknown("unrecognized SQL database engine")
        if not version.startswith(engine):
            return "NOT_APPLICABLE", {"reason": "Different SQL engine"}
        settings = get(item, "settings", dict)
        rows = list_of_objects(optional(settings, "databaseFlags", [], list))
        values = {}
        for row in rows:
            name, value = get(row, "name", str), get(row, "value", str)
            if name in values:
                return unknown("duplicate database flags")
            values[name] = value
        configured = values.get(flag, default)
        if configured is None:
            return unknown("no documented omission default for this source policy")
        return result(configured not in allowed, field=flag, declared=values.get(flag),
            source_omission_value=default, database_version=version,
            semantics="Pinned source omission policy; evidence does not claim that a sentinel/empty string is the database runtime value. No query execution or database contents.")
    cid = rule(query, "sql_instance", evaluate,
        {"databaseVersion": engine + "_16", "settings": {"databaseFlags": [{"name": flag, "value": allowed[0]}]}},
        {"databaseVersion": engine + "_16", "settings": {"databaseFlags": [{"name": flag, "value": bad}]}})
    SQL_SPECS[cid] = {"flag": flag, "default": default, "allowed": allowed, "engine": engine}


sql("reference_sql_pg_min_duration", "POSTGRES", "log_min_duration_statement", "-1", ["-1"], "0")
sql("reference_sql_pg_min_error", "POSTGRES", "log_min_error_statement", "error", ["error"], "panic")
sql("reference_sql_pg_min_messages", "POSTGRES", "log_min_messages", "missing", ["WARNING", "ERROR", "LOG", "FATAL", "PANIC", "warning", "error", "log", "fatal", "panic"], "debug1")
for _flag in ("contained database authentication", "cross db ownership chaining", "external scripts enabled"):
    sql("reference_sqlserver_" + _flag.replace(" ", "_"), "SQLSERVER", _flag, "off", ["off"], "on")
sql("reference_sqlserver_remote_access", "SQLSERVER", "remote access", "on", ["off"], "on")
sql("reference_sqlserver_user_connections", "SQLSERVER", "user connections", "0", ["0"], "10")
sql("reference_sqlserver_user_options", "SQLSERVER", "user options", "", [""], "1")
sql("reference_sqlserver_trace3625", "SQLSERVER", "3625", "off", ["on"], "off")


def alloy_flag(query, flag, allowed=None, presence=False):
    def evaluate(item, index):
        flags = get(item, "databaseFlags", dict)
        if any(not isinstance(value, str) for value in flags.values()):
            raise Unavailable("malformed AlloyDB database flags")
        return result(flag not in flags if presence else flags.get(flag) not in allowed,
            field=flag, declared=flags.get(flag), semantics="Explicit AlloyDB flag declaration, not inherited PostgreSQL default")
    good = {"databaseFlags": {flag: allowed[0] if allowed else "error"}}
    bad = {"databaseFlags": {} if presence else {flag: "terse" if flag == "log_error_verbosity" else "debug1"}}
    rule(query, "alloydb_instance", evaluate, good, bad)


alloy_flag("alloydb_instance_log_error_verbosity_database_flag_default_or_stricter", "log_error_verbosity", ["default", "verbose"])
alloy_flag("alloydb_instance_log_min_messages_database_flag_error", "log_min_messages", ["error", "warning"])
alloy_flag("alloydb_instance_log_min_error_statement_database_flag_configured", "log_min_error_statement", presence=True)


def alloy_encryption(item, index):
    variant = get(item, "encryptionInfo.encryptionType", str)
    if variant not in ("CUSTOMER_MANAGED_ENCRYPTION", "GOOGLE_DEFAULT_ENCRYPTION"):
        return unknown("unrecognized AlloyDB encryption type")
    return result(variant != "CUSTOMER_MANAGED_ENCRYPTION", encryption_type=variant)


rule("alloydb_cluster_encrypted_with_cmk", "alloydb_cluster", alloy_encryption,
    {"encryptionInfo": {"encryptionType": "CUSTOMER_MANAGED_ENCRYPTION"}}, {"encryptionInfo": {"encryptionType": "GOOGLE_DEFAULT_ENCRYPTION"}})


def services(item, index):
    project = get(item, "projectId", str)
    number = optional(item, "name", "", str).removeprefix("projects/")
    prefixes = ["projects/" + value + "/services/" for value in {project, number} if value]
    return [row for row in complete_items(index, "service_usage") if any(get(row, "name", str).startswith(prefix) for prefix in prefixes)]


def service(query, service_name):
    def evaluate(item, index):
        rows = [row for row in services(item, index) if get(row, "name", str).endswith("/services/" + service_name)]
        if len(rows) != 1:
            return unknown("specific service state not collected or ambiguous", service=service_name)
        state = get(rows[0], "state", str)
        if state not in ("ENABLED", "DISABLED"):
            return unknown("unrecognized service state")
        return result(state != "ENABLED", service=service_name, state=state, semantics="Read-only service state; no enablement action")
    cid = rule(query, "project", evaluate, {"projectId": "p"}, {"projectId": "q"}, ["project", "service_usage"])
    CASES[cid]["index"] = {"collections": {"service_usage": [{"status": "collected"}]}, "service_usage": [
        {"data": {"name": "projects/p/services/" + service_name, "state": "ENABLED"}},
        {"data": {"name": "projects/q/services/" + service_name, "state": "DISABLED"}}]}


service("project_service_cloudasset_api_enabled", "cloudasset.googleapis.com")
service("artifacts_container_analysis_enabled", "containeranalysis.googleapis.com")


def gemini(item, index):
    key_name = get(item, "name", str)
    project = key_name.split("/")[1] if key_name.startswith("projects/") else None
    if not project:
        return unknown("API key project identity unavailable")
    state_rows = [row for row in complete_items(index, "service_usage") if get(row, "name", str) == "projects/" + project + "/services/generativelanguage.googleapis.com"]
    if len(state_rows) != 1:
        return unknown("Gemini service state missing or ambiguous")
    state = get(state_rows[0], "state", str)
    if state == "DISABLED":
        return result(False, reason="Gemini API is disabled for this selected key project")
    if state != "ENABLED":
        return unknown("unrecognized service state")
    restrictions = get(item, "restrictions", dict)
    targets = list_of_objects(optional(restrictions, "apiTargets", [], list))
    names = [get(target, "service", str) for target in targets]
    fail = not names or "cloudapis.googleapis.com" in names or len(names) > 1 and "generativelanguage.googleapis.com" in names
    return result(fail, restricted_services=names, semantics="Gemini-specific service/API target declaration; caller restrictions are separate")


cid = rule("apikeys_api_restricted_with_gemini_api", "api_key", gemini,
    {"name": "projects/p/locations/global/keys/k", "restrictions": {"apiTargets": [{"service": "generativelanguage.googleapis.com"}]}},
    {"name": "projects/p/locations/global/keys/k", "restrictions": {"apiTargets": []}}, ["api_key", "service_usage"])
CASES[cid]["index"] = {"collections": {"service_usage": [{"status": "collected"}]}, "service_usage": [{"data": {"name": "projects/p/services/generativelanguage.googleapis.com", "state": "ENABLED"}}]}
