"""Cloud SQL encryption declarations from SQL Admin instances.list.

Pure helper, deliberately unregistered: callers retain their existing check IDs.
This checks encryption enforcement, not client identity or negotiated TLS versions.
"""
from . import result, unknown
from .facts import Unavailable, get, optional


CHECK_IDS = (
    "gcp.ports.sql_instance_require_ssl_enabled",
    "gcp.ports.reference_sql_ssl_connections",
)
SOURCE_URL = "https://docs.cloud.google.com/sql/docs/postgres/admin-api/rest/v1/instances#IpConfiguration"
MODES = frozenset(("ALLOW_UNENCRYPTED_AND_ENCRYPTED", "ENCRYPTED_ONLY",
                   "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"))


def sql_transport(item, index):
    """Classify supported native declarations; absent evidence stays UNKNOWN.

    Explicit sslMode governs; requireSsl is consulted as a fallback only when
    sslMode is absent or unspecified. Invalid native engine/mode pairs and
    incompatible flag combinations do not establish a valid configuration.
    """
    try:
        return _transport(item)
    except Unavailable as exc:
        return unknown(str(exc))


def _transport(item):
    config = get(item, "settings.ipConfiguration", dict)
    mode = optional(config, "sslMode", None, str)
    legacy = optional(config, "requireSsl", None, bool)
    version = optional(item, "databaseVersion", None, str)
    engine = next((prefix for prefix in ("MYSQL", "POSTGRES", "SQLSERVER")
                   if version and version.startswith(prefix + "_")), None)
    evidence = {
        "sslMode": mode, "ssl_mode": mode, "legacy_require_ssl": legacy,
        "database_version": version, "engine": engine,
        "semantics": "Native encryption enforcement declaration; client certificate authentication and runtime TLS negotiation are separate",
    }
    if version is not None and engine is None:
        return unknown("unrecognized Cloud SQL engine", **evidence)
    if mode is None or mode == "SSL_MODE_UNSPECIFIED":
        if legacy is None:
            return unknown("no explicit SSL mode or legacy encryption enforcement observation", **evidence)
        return result(not legacy, deciding_field="settings.ipConfiguration.requireSsl", **evidence)
    if mode not in MODES:
        return unknown("unrecognized SQL SSL mode", **evidence)
    if mode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED" and engine not in ("MYSQL", "POSTGRES"):
        return unknown("trusted-client-certificate SSL mode requires a known MySQL or PostgreSQL engine", **evidence)
    if legacy is not None:
        # Google's IpConfiguration table differs for SQL Server ENCRYPTED_ONLY.
        if mode == "ENCRYPTED_ONLY" and engine is None:
            return unknown("engine required to validate simultaneous SSL mode and legacy flag", **evidence)
        expected = mode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED" or (mode == "ENCRYPTED_ONLY" and engine == "SQLSERVER")
        if legacy != expected:
            return unknown("incompatible native SSL mode and legacy flag combination", **evidence)
    return result(mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
                  deciding_field="settings.ipConfiguration.sslMode", **evidence)
