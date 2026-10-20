"""HackTricks Cloud Best Practices: GCP checks not covered by Prowler/Powerpipe.

Each predicate reads a field the GCP collector already keeps (after sanitize) and is
derived from the cited HackTricks Cloud technique page. Omitted-when-unset defaults
are applied only where the API/collector contract allows it (omitted() requires a
full representation; documented service defaults are explained in the evidence).
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from . import result
from .facts import Unavailable, complete_items, full_representation, get, list_of_objects, omitted, optional
from .fixtures import CASES
from .hacktricks_bp_common import ht_register

GCP = "pentesting-cloud/gcp-security/"
FULL = {"_provenance": {"representation": "full"}}
COMPUTE_DEFAULT = re.compile(r"^[0-9]+-compute@developer\.gserviceaccount\.com$")
CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform"
DEFAULT_SA_REMEDIATION = ("Run the workload as a dedicated user-managed service account holding only the roles it needs; "
                          "the default service account often holds roles/editor on the project.")


def _project(name):
    match = re.match(r"^projects/([^/]+)/", name)
    if not match:
        raise Unavailable("resource name does not carry its project")
    return match.group(1)


# ---------------------------------------------------------------- Cloud Run / Functions identity
def _run_identity(kind, path):
    noun = "service" if kind == "cloudrun_service" else "job"
    cid = "gcp.htbp.cloudrun." + noun + "_no_default_compute_sa"

    @ht_register(cid, "gcp", "least_privilege", kind, "Cloud Run " + noun + " does not run as the Compute Engine default service account",
                 "medium", "AC-6", DEFAULT_SA_REMEDIATION,
                 pages=[GCP + "gcp-services/gcp-cloud-run-enum.md", GCP + "gcp-privilege-escalation/gcp-run-privesc.md"])
    def evaluate(item, index):
        get(item, "name", str)
        labels = optional(item, "labels", {}, dict)
        if labels.get("goog-managed-by") == "cloudfunctions":
            return "NOT_APPLICABLE", {"reason": "Cloud Functions 2nd gen backing service; see gcp.htbp.function.runtime_no_default_sa"}
        template = get(item, path, dict)
        email = optional(template, "serviceAccount", "", str)
        default = not email or bool(COMPUTE_DEFAULT.match(email))
        return result(default, service_account=email or None,
                      semantics="An empty serviceAccount runs the revision/execution as the Compute Engine default service account")
    base = {"name": "projects/p/locations/europe-west1/" + noun + "s/app"}
    def nest(template):
        if kind == "cloudrun_service":
            return {**base, "template": template}
        return {**base, "template": {"template": template}}
    CASES[cid] = {"pass": nest({"serviceAccount": "app@p.iam.gserviceaccount.com"}),
                  "fail": nest({"serviceAccount": "123456789-compute@developer.gserviceaccount.com"}),
                  "missing": base, "malformed": nest({"serviceAccount": 5})}


_run_identity("cloudrun_service", "template")
_run_identity("cloudrun_job", "template.template")

# Variable names that conventionally carry credentials; *_URL/_ID/... names only point at them.
SECRET_NAME = re.compile(r"(?i)passw(or)?d|passwd|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key|conn(ection)?[_-]?str")
NON_SECRET_SUFFIX = re.compile(r"(?i)_(url|uri|path|file|name|id|endpoint|host|port|ttl|length|enabled|version|ref|arn)$")


def _run_env(kind, path):
    noun = "service" if kind == "cloudrun_service" else "job"
    cid = "gcp.htbp.cloudrun." + noun + "_secret_env_from_secret_manager"

    @ht_register(cid, "gcp", "hardening", kind, "Cloud Run " + noun + " sources credential-named environment variables from Secret Manager",
                 "medium", "IA-5", "Store credentials in Secret Manager and reference them with valueSource.secretKeyRef (v2), valueFrom.secretKeyRef (v1), or a "
                 "secret volume instead of literal environment values readable by anyone with run.*.get.",
                 pages=[GCP + "gcp-services/gcp-cloud-run-enum.md", GCP + "gcp-post-exploitation/gcp-cloud-run-post-exploitation.md"])
    def evaluate(item, index):
        template = get(item, path, dict)
        literal = []
        for container in list_of_objects(get(template, "containers", list)):
            for entry in list_of_objects(optional(container, "env", [], list)):
                name = get(entry, "name", str)
                references = [field for field in ("valueSource", "valueFrom")
                              if field in entry or field in entry.get("_coverage", {})]
                if len(references) > 1:
                    raise Unavailable("conflicting Cloud Run environment value sources")
                if references:
                    source = references[0]
                    present = "value" in entry or optional(entry, "_literal_value_present", False, bool)
                    empty = (get(entry, "value", str) == "" if "value" in entry
                             else optional(entry, "_literal_value_empty", False, bool))
                    # v1 permits an explicit empty value beside valueFrom;
                    # v2 value/valueSource are a oneof even when value is empty.
                    if present and (source == "valueSource" or not empty):
                        raise Unavailable("conflicting literal and secret-backed environment value")
                    selector = get(entry, source + ".secretKeyRef", dict)
                    fields = ("secret", "version") if source == "valueSource" else ("name", "key")
                    for field in fields:
                        value = get(selector, field, str)
                        if not value or value != value.strip():
                            raise Unavailable("empty or malformed secret reference " + field)
                    secret = get(selector, fields[0], str)
                    pattern = (r"(?:projects/[A-Za-z0-9_-]+/secrets/)?[A-Za-z0-9_-]+"
                               if source == "valueSource" else r"[A-Za-z0-9_-]+")
                    if not re.fullmatch(pattern, secret):
                        raise Unavailable("malformed Cloud Run secret resource")
                    if not re.fullmatch(r"[A-Za-z0-9_-]+", get(selector, fields[1], str)):
                        raise Unavailable("malformed Cloud Run secret version")
                    continue
                if NON_SECRET_SUFFIX.search(name) or not SECRET_NAME.search(name):
                    continue
                literal.append({"container": container.get("name"), "variable": name})
        return result(bool(literal), literal_credential_variables=literal,
                      semantics="Variable names only (values were never collected); a name heuristic, confirm the value is a credential")
    base = {"name": "projects/p/locations/europe-west1/" + noun + "s/app"}
    def nest(env):
        template = {"containers": [{"name": "app", "image": "gcr.io/p/app", "env": env}]}
        return {**base, "template": template} if kind == "cloudrun_service" else {**base, "template": {"template": template}}
    CASES[cid] = {"pass": nest([{"name": "DB_PASSWORD", "valueSource": {"secretKeyRef": {"secret": "db", "version": "latest"}}},
                                {"name": "TOKEN_URL"}, {"name": "LOG_LEVEL"}]),
                  "fail": nest([{"name": "DB_PASSWORD"}]),
                  "missing": base, "malformed": nest([{"name": 3}])}


_run_env("cloudrun_service", "template")
_run_env("cloudrun_job", "template.template")


@ht_register("gcp.htbp.function.runtime_no_default_sa", "gcp", "least_privilege", "function",
             "Cloud Function does not run as a default (App Engine or Compute Engine) service account", "medium", "AC-6",
             DEFAULT_SA_REMEDIATION,
             pages=[GCP + "gcp-services/gcp-cloud-functions-enum.md", GCP + "gcp-privilege-escalation/gcp-cloudfunctions-privesc.md"])
def function_identity(item, index):
    _project(get(item, "name", str))
    generation = optional(item, "environment", "GEN_2", str)
    if generation not in ("GEN_1", "GEN_2"):
        raise Unavailable("unrecognized function generation")
    config = get(item, "serviceConfig", dict)
    email = optional(config, "serviceAccountEmail", "", str)
    # PROJECT_ID@appspot.gserviceaccount.com is only ever the App Engine default account.
    default = not email or bool(COMPUTE_DEFAULT.match(email)) or email.endswith("@appspot.gserviceaccount.com")
    return result(default, service_account=email or "generation default", environment=generation,
                  semantics="GEN_1 defaults to PROJECT_ID@appspot.gserviceaccount.com, GEN_2 to the Compute Engine default account")


_FN = {"name": "projects/p/locations/europe-west1/functions/f", "environment": "GEN_2"}
CASES["gcp.htbp.function.runtime_no_default_sa"] = {
    "pass": {**_FN, "serviceConfig": {"serviceAccountEmail": "fn@p.iam.gserviceaccount.com"}},
    "fail": {**_FN, "environment": "GEN_1", "serviceConfig": {"serviceAccountEmail": "p@appspot.gserviceaccount.com"}},
    "missing": _FN, "malformed": {**_FN, "serviceConfig": {"serviceAccountEmail": ["x"]}}}


@ht_register("gcp.htbp.appengine.no_default_service_account", "gcp", "least_privilege", "app_engine_application",
             "App Engine application does not run as the App Engine default service account", "medium", "AC-6",
             DEFAULT_SA_REMEDIATION + " Set the application-level serviceAccount (or per-version service accounts).",
             pages=[GCP + "gcp-services/gcp-app-engine-enum.md", GCP + "gcp-privilege-escalation/gcp-appengine-privesc.md"])
def appengine_identity(item, index):
    app_id = get(item, "id", str)
    if get(item, "name", str) != "apps/" + app_id:
        raise Unavailable("application identity mismatch")
    email = optional(item, "serviceAccount", "", str)
    default = not email or email == app_id.split(":")[-1] + "@appspot.gserviceaccount.com"
    return result(default, service_account=email or None,
                  semantics="Application-level default identity; versions may override it with a user-managed account")


CASES["gcp.htbp.appengine.no_default_service_account"] = {
    "pass": {"name": "apps/p", "id": "p", "serviceAccount": "web@p.iam.gserviceaccount.com"},
    "fail": {"name": "apps/p", "id": "p", "serviceAccount": "p@appspot.gserviceaccount.com"},
    "missing": {"name": "apps/p"}, "malformed": {"name": "apps/other", "id": "p"}}


@ht_register("gcp.htbp.instance_template.no_default_sa_full_scope", "gcp", "least_privilege", "instance_template",
             "Instance template does not attach the default compute service account with the cloud-platform scope", "high", "AC-6",
             "Create a new template version with a user-managed service account and minimal scopes, and roll the managed "
             "instance groups to it; VMs created later from the template inherit its identity.",
             pages=[GCP + "gcp-privilege-escalation/gcp-compute-privesc/README.md"])
def template_identity(item, index):
    accounts = list_of_objects(omitted(item, "properties.serviceAccounts", [], list))
    flagged = []
    for account in accounts:
        email = get(account, "email", str)
        scopes = get(account, "scopes", list)
        if any(not isinstance(scope, str) for scope in scopes):
            raise Unavailable("malformed OAuth scope list")
        if COMPUTE_DEFAULT.match(email) and CLOUD_PLATFORM in scopes:
            flagged.append(email)
    return result(bool(flagged), default_accounts_with_full_scope=flagged,
                  semantics="Declared template identity; existing instances are reviewed by the VM checks")


_DEFAULT_ACCOUNT = {"email": "123-compute@developer.gserviceaccount.com", "scopes": [CLOUD_PLATFORM]}
CASES["gcp.htbp.instance_template.no_default_sa_full_scope"] = {
    "pass": {**FULL, "name": "t", "properties": {"serviceAccounts": [{"email": "vm@p.iam.gserviceaccount.com", "scopes": [CLOUD_PLATFORM]}]}},
    "fail": {**FULL, "name": "t", "properties": {"serviceAccounts": [_DEFAULT_ACCOUNT]}},
    "missing": {"name": "t", "properties": {}}, "malformed": {**FULL, "name": "t", "properties": {"serviceAccounts": [{"email": "x", "scopes": "all"}]}}}


# ---------------------------------------------------------------- GKE
@ht_register("gcp.htbp.gke.kubelet_readonly_port_disabled", "gcp", "exposure", "gke_cluster",
             "GKE node pools disable the insecure kubelet read-only port (10255)", "medium", "SC-7",
             "Set insecureKubeletReadonlyPortEnabled=false on the cluster node-pool defaults (nodePoolDefaults / "
             "nodePoolAutoConfig for Autopilot) and on every node pool.",
             pages=[GCP + "gcp-unauthenticated-enum-and-access/gcp-gke-kubelet-unauthenticated-access.md"])
def kubelet_readonly(item, index):
    get(item, "name", str)
    def flag(config, key):
        kubelet = optional(config, key, {}, dict)
        return optional(kubelet, "insecureKubeletReadonlyPortEnabled", None, bool)
    defaults = [flag(optional(optional(item, "nodePoolDefaults", {}, dict), "nodeConfigDefaults", {}, dict), "nodeKubeletConfig"),
                flag(optional(item, "nodePoolAutoConfig", {}, dict), "nodeKubeletConfig")]
    default, auto_default = defaults
    autopilot = optional(optional(item, "autopilot", {}, dict), "enabled", False, bool)
    pools = list_of_objects(optional(item, "nodePools", [], list))
    resolved = {}
    for pool in pools:
        value = flag(optional(pool, "config", {}, dict), "kubeletConfig")
        name = get(pool, "name", str)
        if not name or name in resolved:
            raise Unavailable("node pool identity absent or duplicated")
        automatic = optional(optional(pool, "autoscaling", {}, dict), "autoprovisioned", False, bool)
        inherited = auto_default if (autopilot or automatic) and auto_default is not None else default
        resolved[name] = value if value is not None else inherited
    enabled = sorted(name for name, value in resolved.items() if value is True)
    enabled += [label for label, value in zip(("cluster defaults", "auto-provisioned defaults"), defaults) if value is True]
    if enabled:
        return result(True, enabled_on=enabled)
    if all(value is False for value in resolved.values()) and (resolved or default is False or auto_default is False):
        return result(False, node_pools=sorted(resolved), cluster_default=default)
    return "MANUAL", {"reason": "insecureKubeletReadonlyPortEnabled is not declared; the effective default depends on the GKE "
                                "version at creation (disabled by default for new 1.32+ clusters)", "undeclared_pools": sorted(n for n, v in resolved.items() if v is None)}


def _pool(value):
    return {"name": "pool-1", "config": {"kubeletConfig": {"insecureKubeletReadonlyPortEnabled": value}}}


CASES["gcp.htbp.gke.kubelet_readonly_port_disabled"] = {
    "pass": {"name": "c", "nodePools": [_pool(False)]}, "fail": {"name": "c", "nodePools": [_pool(False), {**_pool(True), "name": "pool-2"}]},
    "manual": {"name": "c", "nodePools": [{"name": "pool-1", "config": {}}]},
    "missing": {"location": "europe-west1"}, "malformed": {"name": "c", "nodePools": [_pool("yes")]}}


# ---------------------------------------------------------------- Logging / KMS / Storage
@ht_register("gcp.htbp.logging.default_sink_not_disabled", "gcp", "hardening", "log_sink",
             "Project _Default log sink is not disabled", "medium", "AU-9",
             "Re-enable the _Default sink (gcloud logging sinks update _Default --no-disabled) or document the aggregated "
             "organization/folder sink that replaces it; a disabled _Default sink stops routing non-audit logs.",
             pages=[GCP + "gcp-post-exploitation/gcp-logging-post-exploitation.md"])
def default_sink(item, index):
    name = get(item, "name", str)
    if not (name.startswith("projects/") and name.endswith("/sinks/_Default")):
        return "NOT_APPLICABLE", {"reason": "only the project _Default sink is evaluated"}
    disabled = optional(item, "disabled", False, bool)
    return result(disabled, sink=name, disabled=disabled)


CASES["gcp.htbp.logging.default_sink_not_disabled"] = {
    "pass": {"name": "projects/p/sinks/_Default", "destination": "logging.googleapis.com/projects/p/locations/global/buckets/_Default"},
    "fail": {"name": "projects/p/sinks/_Default", "destination": "logging.googleapis.com/projects/p/locations/global/buckets/_Default", "disabled": True},
    "missing": {"destination": "x"}, "malformed": {"name": "projects/p/sinks/_Default", "disabled": "true"}}

SECONDS = re.compile(r"^([0-9]+)(?:\.[0-9]{1,9})?s$")
WEEK = 7 * 86400


@ht_register("gcp.htbp.kms.destroy_window_not_shortened", "gcp", "hardening", "kms_key",
             "Cloud KMS key keeps a destroy-scheduled window of at least 7 days", "medium", "CP-9",
             "destroyScheduledDuration is immutable: create a replacement key with the default 30-day window, re-encrypt, "
             "and enforce constraints/cloudkms.minimumDestroyScheduledDuration.",
             pages=[GCP + "gcp-post-exploitation/gcp-kms-post-exploitation.md"])
def destroy_window(item, index):
    duration = omitted(item, "destroyScheduledDuration", "2592000s", str)
    match = SECONDS.match(duration)
    if not match:
        raise Unavailable("invalid protobuf duration")
    seconds = int(match.group(1))
    return result(seconds < WEEK, destroy_scheduled_duration=duration,
                  semantics="Shorter windows shrink the time to notice and restore a scheduled key-version destruction")


CASES["gcp.htbp.kms.destroy_window_not_shortened"] = {
    "pass": {**FULL, "name": "projects/p/locations/global/keyRings/r/cryptoKeys/k", "purpose": "ENCRYPT_DECRYPT"},
    "fail": {**FULL, "name": "projects/p/locations/global/keyRings/r/cryptoKeys/k", "destroyScheduledDuration": "86400s"},
    "missing": {"name": "projects/p/locations/global/keyRings/r/cryptoKeys/k"},
    "malformed": {**FULL, "name": "k", "destroyScheduledDuration": "1d"}}

PUBLIC_ENTITIES = {"allUsers", "allAuthenticatedUsers"}


@ht_register("gcp.htbp.storage.default_object_acl_not_public", "gcp", "exposure", "bucket",
             "Bucket default object ACL does not make new objects public", "high", "AC-3",
             "Enable uniform bucket-level access (or remove allUsers/allAuthenticatedUsers from the default object ACL); "
             "the bucket IAM policy does not show default-object-ACL grants.",
             pages=[GCP + "gcp-persistence/gcp-storage-persistence.md"])
def default_object_acl(item, index):
    get(item, "name", str)
    if omitted(item, "iamConfiguration.uniformBucketLevelAccess.enabled", False, bool):
        return "NOT_APPLICABLE", {"reason": "uniform bucket-level access disables object ACLs"}
    entries = list_of_objects(get(item, "defaultObjectAcl", list))
    public = sorted({get(entry, "entity", str) for entry in entries} & PUBLIC_ENTITIES)
    return result(bool(public), public_entities=public,
                  semantics="Default object ACL applies to every future object; absent with fine-grained access means unreadable")


_BUCKET = {**FULL, "name": "b", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}}}
CASES["gcp.htbp.storage.default_object_acl_not_public"] = {
    "pass": {**_BUCKET, "defaultObjectAcl": [{"entity": "project-owners-1", "role": "OWNER"}]},
    "fail": {**_BUCKET, "defaultObjectAcl": [{"entity": "allUsers", "role": "READER"}]},
    "missing": {**_BUCKET}, "malformed": {**_BUCKET, "defaultObjectAcl": "allUsers"}}


# ---------------------------------------------------------------- Pub/Sub
EXFIL_HOST = re.compile(r"(?i)(^|\.)(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|webhook\.site|requestbin\.(com|net)|"
                        r"pipedream\.net|beeceptor\.com|interact\.sh|oast\.(fun|live|me|online|pro|site)|burpcollaborator\.net|"
                        r"serveo\.net|localtunnel\.me|loca\.lt)$")


@ht_register("gcp.htbp.pubsub.push_endpoint_not_tunnel", "gcp", "exposure", "pubsub_subscription",
             "Pub/Sub push subscription does not deliver to a raw IP or tunnel/request-capture host", "medium", "SC-7",
             "Point push subscriptions at owned HTTPS endpoints (Cloud Run, Functions, owned domains) and enforce "
             "constraints/pubsub.allowedPushSubscriptionEndpoints.",
             pages=[GCP + "gcp-post-exploitation/gcp-pub-sub-post-exploitation.md"])
def push_endpoint(item, index):
    get(item, "name", str)
    push = optional(item, "pushConfig", {}, dict)
    endpoint = optional(push, "pushEndpoint", "", str)
    if not endpoint:
        return "NOT_APPLICABLE", {"reason": "pull, export or unconfigured subscription"}
    host = (urlsplit(endpoint).hostname or "").rstrip(".")
    if not host:
        raise Unavailable("push endpoint has no host")
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    return result(literal or bool(EXFIL_HOST.search(host)), push_host=host, ip_literal=literal,
                  semantics="Only IP literals and known tunnel/request-capture services fail; other hosts need ownership review")


_SUB = {"name": "projects/p/subscriptions/s", "topic": "projects/p/topics/t"}
CASES["gcp.htbp.pubsub.push_endpoint_not_tunnel"] = {
    "pass": {**_SUB, "pushConfig": {"pushEndpoint": "https://worker-abc-ew.a.run.app/push"}},
    "fail": {**_SUB, "pushConfig": {"pushEndpoint": "https://abcd.ngrok-free.app/x"}},
    "missing": {"topic": "projects/p/topics/t"}, "malformed": {**_SUB, "pushConfig": {"pushEndpoint": 1}}}


# ---------------------------------------------------------------- Artifact Registry
@ht_register("gcp.htbp.artifactregistry.virtual_repo_private_precedence", "gcp", "hardening", "artifact_repository",
             "Artifact Registry virtual repository gives private upstreams precedence over remote (public) upstreams", "high", "SI-7",
             "Give every standard (private) upstream a strictly higher priority than any remote upstream, or serve internal "
             "package names only from the private repository (dependency confusion).",
             pages=[GCP + "gcp-persistence/gcp-artifact-registry-persistence.md"], dependencies=["artifact_repository"])
def virtual_precedence(item, index):
    get(item, "name", str)
    mode = get(item, "mode", str)
    if mode not in ("STANDARD_REPOSITORY", "REMOTE_REPOSITORY", "VIRTUAL_REPOSITORY"):
        raise Unavailable("unrecognized Artifact Registry repository mode")
    if mode != "VIRTUAL_REPOSITORY":
        return "NOT_APPLICABLE", {"reason": "not a virtual repository"}
    policies = list_of_objects(get(item, "virtualRepositoryConfig.upstreamPolicies", list))
    modes = {get(repo, "name", str): get(repo, "mode", str) for repo in complete_items(index, "artifact_repository")}
    priorities = {"STANDARD_REPOSITORY": [], "REMOTE_REPOSITORY": []}
    for policy in policies:
        upstream = get(policy, "repository", str)
        if upstream not in modes:
            raise Unavailable("upstream repository not in the collected inventory: " + upstream)
        if modes[upstream] not in ("STANDARD_REPOSITORY", "REMOTE_REPOSITORY"):
            raise Unavailable("nested or unrecognized upstream mode needs independent resolution")
        priority = optional(policy, "priority", 0, int)
        priorities[modes[upstream]].append(priority)
    private, remote = priorities["STANDARD_REPOSITORY"], priorities["REMOTE_REPOSITORY"]
    if not private or not remote:
        return result(False, standard_priorities=private, remote_priorities=remote,
                      semantics="No mix of private and remote upstreams")
    return result(max(remote) >= min(private), standard_priorities=private, remote_priorities=remote,
                  semantics="Higher priority wins; equal priorities are not deterministic")


def _ar_index(remote_priority):
    repos = [{"name": "projects/p/locations/us/repositories/" + n, "mode": m} for n, m in
             (("private", "STANDARD_REPOSITORY"), ("pypi", "REMOTE_REPOSITORY"), ("virt", "VIRTUAL_REPOSITORY"))]
    item = {"name": "projects/p/locations/us/repositories/virt", "mode": "VIRTUAL_REPOSITORY", "virtualRepositoryConfig": {"upstreamPolicies": [
        {"id": "a", "repository": "projects/p/locations/us/repositories/private", "priority": 100},
        {"id": "b", "repository": "projects/p/locations/us/repositories/pypi", "priority": remote_priority}]}}
    index = {"collections": {"artifact_repository": [{"scope": "projects/p", "status": "collected"}]},
             "artifact_repository": [{"data": repo} for repo in repos]}
    return item, index


_AR_PASS, _AR_INDEX = _ar_index(10)
_AR_FAIL, _ = _ar_index(100)
CASES["gcp.htbp.artifactregistry.virtual_repo_private_precedence"] = {
    "pass": _AR_PASS, "fail": _AR_FAIL, "index": _AR_INDEX,
    "missing": {"name": "projects/p/locations/us/repositories/virt", "mode": "VIRTUAL_REPOSITORY"},
    "malformed": {"name": "projects/p/locations/us/repositories/virt", "mode": "VIRTUAL_REPOSITORY", "virtualRepositoryConfig": {"upstreamPolicies": "x"}}}


# ---------------------------------------------------------------- Functions environment (names only)
@ht_register("gcp.htbp.function.secret_env_from_secret_manager", "gcp", "hardening", "function",
             "Cloud Function sources credential-named environment variables from Secret Manager", "medium", "IA-5",
             "Move credentials to Secret Manager and expose them with secretEnvironmentVariables / secret volumes instead of "
             "literal serviceConfig.environmentVariables readable by anyone with cloudfunctions.functions.get.",
             pages=[GCP + "gcp-services/gcp-cloud-functions-enum.md", GCP + "gcp-privilege-escalation/gcp-cloudfunctions-privesc.md"])
def function_env(item, index):
    _project(get(item, "name", str))
    config = get(item, "serviceConfig", dict)
    # Collector marker: names list present only when the inline map was read (values never are).
    names = get(config, "environmentVariableNames", list)
    if any(not isinstance(name, str) for name in names):
        raise Unavailable("malformed environment variable names")
    literal = sorted(name for name in names if SECRET_NAME.search(name) and not NON_SECRET_SUFFIX.search(name))
    secret_backed = sorted(x.get("key") for x in list_of_objects(optional(config, "secretEnvironmentVariables", [], list)))
    return result(bool(literal), literal_credential_variables=literal, secret_manager_variables=secret_backed,
                  semantics="Variable names only (values were never collected); a name heuristic, confirm the value is a credential")


CASES["gcp.htbp.function.secret_env_from_secret_manager"] = {
    "pass": {**_FN, "serviceConfig": {"environmentVariableNames": ["DB_HOST", "TOKEN_URL"],
                                      "secretEnvironmentVariables": [{"key": "DB_PASSWORD", "secret": "db", "version": "latest"}]}},
    "fail": {**_FN, "serviceConfig": {"environmentVariableNames": ["STRIPE_API_KEY"]}},
    "missing": {**_FN, "serviceConfig": {}}, "malformed": {**_FN, "serviceConfig": {"environmentVariableNames": [1]}}}


# ---------------------------------------------------------------- Cloud Build triggers
CLOUDBUILD_LEGACY = re.compile(r"^[0-9]+@cloudbuild\.gserviceaccount\.com$")
_CB_PAGES = [GCP + "gcp-unauthenticated-enum-and-access/gcp-cloud-build-unauthenticated-enum.md",
             GCP + "gcp-services/gcp-cloud-build-enum.md"]


def _trigger_enabled(item):
    get(item, "resourceName", str)
    disabled = omitted(item, "disabled", False, bool)
    return not disabled


def _pull_request(item):
    sources = [source for source in (optional(item, field, None, dict)
               for field in ("github", "repositoryEventConfig", "developerConnectEventConfig")) if source is not None]
    if len(sources) > 1:
        raise Unavailable("conflicting trigger source declarations")
    for source in sources:
        if "pullRequest" in source or "pullRequest" in source.get("_coverage", {}):
            return get(source, "pullRequest", dict)
    return None


@ht_register("gcp.htbp.cloudbuild.pr_trigger_gated", "gcp", "least_privilege", "cloudbuild_trigger",
             "Pull-request Cloud Build trigger requires a /gcbrun comment or build approval", "high", "CM-5",
             "Set the pull-request comment control to 'Required' (or 'Required except for owners and collaborators') or enable "
             "approvalConfig.approvalRequired, so untrusted contributors cannot run a modified cloudbuild.yaml as the trigger's "
             "service account.",
             pages=_CB_PAGES)
def cloudbuild_pr(item, index):
    if not _trigger_enabled(item):
        return "NOT_APPLICABLE", {"reason": "trigger disabled"}
    pull_request = _pull_request(item)
    if pull_request is None:
        return "NOT_APPLICABLE", {"reason": "not a pull-request trigger"}
    approval = optional(omitted(item, "approvalConfig", {}, dict), "approvalRequired", False, bool)
    # proto3 JSON omits the zero enum COMMENTS_DISABLED ("Not required").
    control = optional(pull_request, "commentControl", "COMMENTS_DISABLED", str) if full_representation(item) else get(pull_request, "commentControl", str)
    if control not in ("COMMENTS_DISABLED", "COMMENTS_ENABLED", "COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY"):
        raise Unavailable("unrecognized commentControl")
    return result(control == "COMMENTS_DISABLED" and not approval, comment_control=control, approval_required=approval,
                  service_account=item.get("serviceAccount") or "project default",
                  semantics="COMMENTS_DISABLED ('Not required') builds every matching pull request, including forks")


def _trigger_email(value):
    return value.rsplit("/", 1)[-1] if value.startswith("projects/") else value


@ht_register("gcp.htbp.cloudbuild.trigger_no_default_sa", "gcp", "least_privilege", "cloudbuild_trigger",
             "Cloud Build trigger runs as a dedicated service account, not a default build identity", "medium", "AC-6",
             "Set the trigger serviceAccount to a dedicated least-privilege account; the legacy Cloud Build account and the "
             "Compute Engine default account frequently hold broad project roles, and every repository writer inherits them.",
             pages=[GCP + "gcp-privilege-escalation/gcp-cloudbuild-privesc.md", _CB_PAGES[0]])
def cloudbuild_sa(item, index):
    if not _trigger_enabled(item):
        return "NOT_APPLICABLE", {"reason": "trigger disabled"}
    email = _trigger_email(omitted(item, "serviceAccount", "", str))
    default = not email or bool(COMPUTE_DEFAULT.match(email) or CLOUDBUILD_LEGACY.match(email))
    return result(default, service_account=email or None,
                  semantics="An unset trigger serviceAccount uses the project's default build identity (legacy Cloud Build or Compute Engine default)")


_TRIGGER = {**FULL, "id": "1", "name": "pr", "resourceName": "projects/p/locations/global/triggers/1"}
CASES["gcp.htbp.cloudbuild.pr_trigger_gated"] = {
    "pass": {**_TRIGGER, "github": {"owner": "o", "name": "r", "pullRequest": {"branch": "^main$", "commentControl": "COMMENTS_ENABLED"}}},
    "fail": {**_TRIGGER, "github": {"owner": "o", "name": "r", "pullRequest": {"branch": "^main$"}}},
    "not_applicable": {**_TRIGGER, "github": {"owner": "o", "name": "r", "push": {"branch": "^main$"}}},
    "missing": {"id": "1", "resourceName": "projects/p/locations/global/triggers/1", "github": {"pullRequest": {"branch": "^main$"}}},
    "malformed": {**_TRIGGER, "github": {"pullRequest": {"commentControl": 3}}}}
CASES["gcp.htbp.cloudbuild.trigger_no_default_sa"] = {
    "pass": {**_TRIGGER, "serviceAccount": "projects/p/serviceAccounts/build@p.iam.gserviceaccount.com"},
    "fail": {**_TRIGGER, "serviceAccount": "projects/p/serviceAccounts/123-compute@developer.gserviceaccount.com"},
    "missing": {"id": "1", "resourceName": "projects/p/locations/global/triggers/1"},
    "malformed": {**_TRIGGER, "serviceAccount": 7}}


# ---------------------------------------------------------------- Storage HMAC keys
HMAC_MAX_AGE_DAYS = 90


def _parse_time(value):
    from datetime import datetime, timezone
    if not isinstance(value, str):
        raise Unavailable("timestamp missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Unavailable("malformed timestamp")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@ht_register("gcp.htbp.storage.hmac_key_not_stale_or_default_sa", "gcp", "least_privilege", "storage_hmac_key",
             "Active Cloud Storage HMAC key is recent and not bound to a default service account", "medium", "IA-5",
             "Deactivate and delete HMAC keys older than 90 days or bound to default service accounts; enforce "
             "constraints/iam.disableServiceAccountKeyCreation, which also blocks new HMAC keys.",
             pages=[GCP + "gcp-cross-project-attacks/resource-sharing-and-confused-deputy-attacks.md",
                    GCP + "gcp-post-exploitation/gcp-storage-post-exploitation.md"])
def hmac_key(item, index):
    get(item, "accessId", str)
    state = get(item, "state", str)
    if state in ("INACTIVE", "DELETED"):
        return "NOT_APPLICABLE", {"reason": "HMAC key " + state.lower()}
    if state != "ACTIVE":
        raise Unavailable("unrecognized HMAC key state")
    email = get(item, "serviceAccountEmail", str)
    created = _parse_time(get(item, "timeCreated", str))
    provenance = item.get("_provenance") if isinstance(item.get("_provenance"), dict) else {}
    captured = provenance.get("collected_at") or (index.get("context") or {}).get("created_at")
    age = (_parse_time(captured) - created).days
    default = bool(COMPUTE_DEFAULT.match(email)) or email.endswith("@appspot.gserviceaccount.com")
    return result(age > HMAC_MAX_AGE_DAYS or default, service_account=email, age_days=age, default_service_account=default,
                  semantics="HMAC keys are long-lived S3-interoperable credentials carrying the bound account's permissions")


_HMAC = {"accessId": "GOOG1", "state": "ACTIVE", "serviceAccountEmail": "sync@p.iam.gserviceaccount.com",
         "_provenance": {"collected_at": "2026-10-10T00:00:00Z"}}
CASES["gcp.htbp.storage.hmac_key_not_stale_or_default_sa"] = {
    "pass": {**_HMAC, "timeCreated": "2026-09-01T00:00:00Z"}, "fail": {**_HMAC, "timeCreated": "2025-01-01T00:00:00Z"},
    "not_applicable": {**_HMAC, "state": "INACTIVE", "timeCreated": "2025-01-01T00:00:00Z"},
    "missing": {"accessId": "GOOG1", "state": "ACTIVE"}, "malformed": {**_HMAC, "timeCreated": "yesterday"}}


# ---------------------------------------------------------------- Composer / Workbench identities
@ht_register("gcp.htbp.composer.no_default_compute_sa", "gcp", "least_privilege", "composer_environment",
             "Cloud Composer environment does not run as the Compute Engine default service account", "high", "AC-6",
             DEFAULT_SA_REMEDIATION + " Anyone who can write DAGs to the environment bucket runs code as this identity.",
             pages=[GCP + "gcp-privilege-escalation/gcp-composer-privesc.md", GCP + "gcp-services/gcp-vertex-ai-enum.md"])
def composer_identity(item, index):
    _project(get(item, "name", str))
    config = get(item, "config", dict)
    node = optional(config, "nodeConfig", {}, dict)
    email = optional(node, "serviceAccount", "", str)
    return result(not email or bool(COMPUTE_DEFAULT.match(email)), service_account=email or None,
                  semantics="An unset nodeConfig.serviceAccount is the Compute Engine default service account")


_COMPOSER = {"name": "projects/p/locations/us-central1/environments/e"}
CASES["gcp.htbp.composer.no_default_compute_sa"] = {
    "pass": {**_COMPOSER, "config": {"nodeConfig": {"serviceAccount": "airflow@p.iam.gserviceaccount.com"}}},
    "fail": {**_COMPOSER, "config": {"nodeConfig": {}}}, "missing": _COMPOSER,
    "malformed": {**_COMPOSER, "config": {"nodeConfig": {"serviceAccount": ["x"]}}}}


@ht_register("gcp.htbp.workbench.no_default_compute_sa", "gcp", "least_privilege", "workbench_instance",
             "Vertex AI Workbench instance does not run as the Compute Engine default service account", "medium", "AC-6",
             DEFAULT_SA_REMEDIATION + " Notebook, terminal and startup-script code all use the attached account's credentials.",
             pages=[GCP + "gcp-privilege-escalation/gcp-vertex-ai-privesc.md", GCP + "gcp-services/gcp-vertex-ai-enum.md"])
def workbench_identity(item, index):
    _project(get(item, "name", str))
    setup = get(item, "gceSetup", dict)
    accounts = list_of_objects(optional(setup, "serviceAccounts", [], list))
    emails = [get(account, "email", str) for account in accounts]
    return result(not emails or any(COMPUTE_DEFAULT.match(email) for email in emails), service_accounts=emails,
                  semantics="Without gceSetup.serviceAccounts the instance VM uses the Compute Engine default service account")


_NB = {"name": "projects/p/locations/us-central1-a/instances/nb"}
CASES["gcp.htbp.workbench.no_default_compute_sa"] = {
    "pass": {**_NB, "gceSetup": {"serviceAccounts": [{"email": "nb@p.iam.gserviceaccount.com"}]}},
    "fail": {**_NB, "gceSetup": {"serviceAccounts": [{"email": "1-compute@developer.gserviceaccount.com"}]}},
    "missing": _NB, "malformed": {**_NB, "gceSetup": {"serviceAccounts": [{"email": 1}]}}}


# ---------------------------------------------------------------- Cloud Scheduler self-healing backdoor
# Google API write methods that re-grant access when replayed on a schedule.
IAM_REPLAY = re.compile(r"(?i)(:setIamPolicy$|/serviceAccounts/[^/]+/keys$|/hmacKeys$|/global/firewalls$"
                        r"|/storage/v1/b/[^/]+/(iam|acl|defaultObjectAcl)$)")


@ht_register("gcp.htbp.scheduler.no_recurring_access_regrant", "gcp", "least_privilege", "scheduler_job",
             "Cloud Scheduler job does not replay IAM/key/firewall writes as a service account", "high", "AC-2",
             "Review and delete scheduled jobs that call setIamPolicy, create service-account or HMAC keys, firewall rules or "
             "bucket ACL/IAM changes with an OAuth token: they re-create access on a schedule and survive removal of the "
             "original grant.",
             pages=[GCP + "gcp-persistence/gcp-cloud-scheduler-persistence.md", GCP + "gcp-privilege-escalation/gcp-cloudscheduler-privesc.md"])
def scheduler_replay(item, index):
    get(item, "name", str)
    state = get(item, "state", str)
    if state in ("PAUSED", "DISABLED"):
        return "NOT_APPLICABLE", {"reason": "job " + state.lower()}
    if state not in ("ENABLED", "UPDATE_FAILED"):
        raise Unavailable("unrecognized job state")
    target = optional(item, "httpTarget", None)
    if target is None:
        return "NOT_APPLICABLE", {"reason": "not an HTTP target job"}
    if not isinstance(target, dict):
        raise Unavailable("malformed httpTarget")
    if "oauthToken" not in target:
        return "NOT_APPLICABLE", {"reason": "no OAuth token: cannot call Google APIs as a service account"}
    identity = get(target, "oauthToken", dict).get("serviceAccountEmail")
    parts = urlsplit(get(target, "uri", str))
    method = optional(target, "httpMethod", "POST", str)
    replay = (parts.hostname or "").endswith(".googleapis.com") and method in ("POST", "PUT", "PATCH") and bool(IAM_REPLAY.search(parts.path))
    return result(replay, uri=f"{parts.scheme}://{parts.hostname}{parts.path}", http_method=method, service_account=identity,
                  semantics="Write to an access-granting Google API method on a schedule (self-healing persistence pattern)")


_JOB = {"name": "projects/p/locations/us-central1/jobs/j", "state": "ENABLED"}
_OAUTH = {"serviceAccountEmail": "ops@p.iam.gserviceaccount.com"}
CASES["gcp.htbp.scheduler.no_recurring_access_regrant"] = {
    "pass": {**_JOB, "httpTarget": {"uri": "https://run.googleapis.com/v2/projects/p/locations/r/jobs/x:run", "httpMethod": "POST", "oauthToken": _OAUTH}},
    "fail": {**_JOB, "httpTarget": {"uri": "https://cloudresourcemanager.googleapis.com/v1/projects/p:setIamPolicy", "oauthToken": _OAUTH}},
    "not_applicable": {**_JOB, "pubsubTarget": {"topicName": "projects/p/topics/t"}},
    "missing": {"name": "projects/p/locations/us-central1/jobs/j"},
    "malformed": {**_JOB, "httpTarget": {"uri": 5, "oauthToken": _OAUTH}}}


# ---------------------------------------------------------------- Effective Organization Policy guardrails
# org_policy_effective rows are orgpolicy v2 getEffectivePolicy results (the
# project's policy merged with its folder/organization ancestors), one per
# constraint in peaso.collectors.gcp.ORG_POLICY_CONSTRAINTS.
_ORGPOL = GCP + "gcp-privilege-escalation/gcp-orgpolicy-privesc.md"
_XPROJ = GCP + "gcp-cross-project-attacks/detection-and-hardening.md"


def _effective_rules(index, constraint):
    """(policy name, unconditional rules) or None when nothing is set in the hierarchy."""
    rows = [p for p in complete_items(index, "org_policy_effective") if p.get("constraint") == constraint]
    if len(rows) != 1:
        raise Unavailable("effective org policy missing or ambiguous: " + constraint)
    spec = optional(rows[0], "spec", {}, dict)
    rules = list_of_objects(optional(spec, "rules", [], list))
    if any("condition" in rule for rule in rules):
        # Tag/resource-conditioned rules: the result depends on each resource.
        raise Unavailable("conditional effective org policy rule: " + constraint)
    return (rows[0].get("name"), rules) if rules else None


def _boolean(index, constraint):
    """True/False when a boolean (legacy or managed) constraint has rules, None when unset."""
    found = _effective_rules(index, constraint)
    if found is None:
        return None
    _, rules = found
    if any(set(rule) - {"enforce", "parameters"} for rule in rules):
        raise Unavailable("non-boolean effective org policy rule: " + constraint)
    values = {get(rule, "enforce", bool) for rule in rules}
    if len(values) > 1:
        raise Unavailable("contradictory effective org policy rules: " + constraint)
    return values == {True}


def _list_restricted(index, constraint):
    """Whether a list constraint restricts values (allowedValues/denyAll); False when unset or allowAll."""
    found = _effective_rules(index, constraint)
    if found is None:
        return False, []
    _, rules = found
    if any(set(rule) - {"values", "allowAll", "denyAll"} for rule in rules):
        raise Unavailable("non-list effective org policy rule: " + constraint)
    if any(optional(rule, "allowAll", False, bool) for rule in rules):
        return False, []
    if any(optional(rule, "denyAll", False, bool) for rule in rules):
        return True, []
    allowed = []
    for rule in rules:
        values = optional(rule, "values", {}, dict)
        entries = optional(values, "allowedValues", [], list)
        if any(not isinstance(entry, str) for entry in entries):
            raise Unavailable("malformed allowedValues: " + constraint)
        allowed.extend(entries)
    return bool(allowed), sorted(set(allowed))


# Unset (no effective rule) is treated as "not enforced" only for constraints whose documented default
# is not enforced and that HackTricks lists as hardening gaps (key creation/upload, automatic default-SA
# grants, DRS, essential contacts). Secure-by-default orgs (created on/after 2024-05-03) get these as
# materialized org-level policies, which getEffectivePolicy returns, so no default is assumed here.
def _managed_or_legacy(index, managed, legacy):
    """A managed constraint with rules supersedes its legacy boolean twin."""
    value = _boolean(index, managed)
    if value is not None:
        return value, managed
    return bool(_boolean(index, legacy)), legacy


def _project_scope(item):
    name = get(item, "name", str)
    if not name.startswith("projects/"):
        raise Unavailable("not a project resource")
    return name


@ht_register("gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked", "gcp", "least_privilege", "project",
             "Effective org policy blocks service-account key creation and key upload", "medium", "IA-5",
             "Enforce constraints/iam.managed.disableServiceAccountKeyCreation and iam.managed.disableServiceAccountKeyUpload "
             "(or their legacy booleans) at the organization and avoid project-level overrides; exported or uploaded keys are "
             "long-lived backdoors for the service account.",
             pages=[_XPROJ, GCP + "gcp-cross-project-attacks/iam-and-service-account-impersonation-attacks.md", _ORGPOL,
                    GCP + "gcp-privilege-escalation/gcp-iam-privesc.md"],
             dependencies=["project", "org_policy_effective"])
def orgpolicy_sa_keys(item, index):
    scope = _project_scope(item)
    create, create_from = _managed_or_legacy(index, "iam.managed.disableServiceAccountKeyCreation", "iam.disableServiceAccountKeyCreation")
    upload, upload_from = _managed_or_legacy(index, "iam.managed.disableServiceAccountKeyUpload", "iam.disableServiceAccountKeyUpload")
    return result(not (create and upload), project=scope, key_creation_blocked=create, key_creation_constraint=create_from,
                  key_upload_blocked=upload, key_upload_constraint=upload_from,
                  semantics="Managed iam.managed.* constraints supersede the legacy booleans when they carry a policy")


@ht_register("gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled", "gcp", "least_privilege", "project",
             "Effective org policy keeps cross-project service-account attachment disabled", "medium", "AC-6",
             "Set an explicit enforce:true policy for iam.disableCrossProjectServiceAccountUsage at the organization (the "
             "secure-by-default policy exists only on organizations created on or after 2024-05-03); when a shared deployer "
             "account is required, scope the exception to that single project.",
             pages=[_ORGPOL, _XPROJ, GCP + "gcp-cross-project-attacks/iam-and-service-account-impersonation-attacks.md"],
             dependencies=["project", "org_policy_effective"])
def orgpolicy_cross_project(item, index):
    scope = _project_scope(item)
    value = _boolean(index, "iam.disableCrossProjectServiceAccountUsage")
    if value is None:
        # Secure-by-default enforcement exists only for organizations created on/after 2024-05-03 and is
        # materialized as an org-level policy, which getEffectivePolicy would return. An empty effective
        # policy (older org, or a project without an organization) has no reliable default signal.
        raise Unavailable("iam.disableCrossProjectServiceAccountUsage has no effective policy; enforcement cannot be "
                          "inferred. Set an explicit enforce:true policy at the organization (or project) level.")
    return result(not value, project=scope, enforced=value, explicit_policy=True,
                  semantics="PASS only on an explicit effective enforce:true; unset is UNKNOWN (no default assumed)")


@ht_register("gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled", "gcp", "least_privilege", "project",
             "Effective org policy stops automatic Editor grants to new default service accounts", "medium", "AC-6",
             "Enforce iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts or iam.automaticIamGrantsForDefaultServiceAccounts "
             "and remove roles/editor from existing default service accounts.",
             pages=[_ORGPOL, _XPROJ], dependencies=["project", "org_policy_effective"])
def orgpolicy_default_sa(item, index):
    scope = _project_scope(item)
    enforced, source = _managed_or_legacy(index, "iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts",
                                          "iam.automaticIamGrantsForDefaultServiceAccounts")
    return result(not enforced, project=scope, enforced=enforced, constraint=source,
                  semantics="Only affects default service accounts created later; existing Editor grants are reported by IAM checks")


@ht_register("gcp.htbp.orgpolicy.domain_restricted_sharing", "gcp", "exposure", "project",
             "Effective org policy restricts IAM members to allowed domains (Domain Restricted Sharing)", "medium", "AC-3",
             "Enforce iam.managed.allowedPolicyMembers or iam.allowedPolicyMemberDomains (allowed customer IDs/principal sets) so "
             "allUsers, allAuthenticatedUsers and external accounts cannot be bound to project resources.",
             pages=[GCP + "gcp-cross-project-attacks/iam-and-service-account-impersonation-attacks.md", _ORGPOL,
                    GCP + "gcp-persistence/gcp-cloud-functions-persistence.md"],
             dependencies=["project", "org_policy_effective"])
def orgpolicy_drs(item, index):
    scope = _project_scope(item)
    managed = _boolean(index, "iam.managed.allowedPolicyMembers")
    if managed is not None:
        return result(not managed, project=scope, enforced=managed, constraint="iam.managed.allowedPolicyMembers")
    restricted, allowed = _list_restricted(index, "iam.allowedPolicyMemberDomains")
    return result(not restricted, project=scope, enforced=restricted, allowed_values=allowed, constraint="iam.allowedPolicyMemberDomains")


@ht_register("gcp.htbp.orgpolicy.essential_contacts_domain_restricted", "gcp", "hardening", "project",
             "Effective org policy restricts Essential Contacts to allowed domains", "low", "IR-6",
             "Enforce essentialcontacts.managed.allowedContactDomains or essentialcontacts.allowedContactDomains with the "
             "organization's domains so an attacker cannot register an external address that receives security notifications.",
             pages=[GCP + "gcp-persistence/gcp-essential-contacts-persistence.md"], dependencies=["project", "org_policy_effective"])
def orgpolicy_contacts(item, index):
    scope = _project_scope(item)
    managed = _boolean(index, "essentialcontacts.managed.allowedContactDomains")
    if managed is not None:
        return result(not managed, project=scope, enforced=managed, constraint="essentialcontacts.managed.allowedContactDomains")
    restricted, allowed = _list_restricted(index, "essentialcontacts.allowedContactDomains")
    return result(not restricted, project=scope, enforced=restricted, allowed_values=allowed,
                  constraint="essentialcontacts.allowedContactDomains")


def _orgpol_index(**rules):
    """Fixture: every requested constraint evaluated; `rules` maps constraint -> rule list."""
    names = ("iam.disableServiceAccountKeyCreation", "iam.managed.disableServiceAccountKeyCreation",
             "iam.disableServiceAccountKeyUpload", "iam.managed.disableServiceAccountKeyUpload",
             "iam.disableCrossProjectServiceAccountUsage", "iam.automaticIamGrantsForDefaultServiceAccounts",
             "iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts", "iam.allowedPolicyMemberDomains",
             "iam.managed.allowedPolicyMembers", "essentialcontacts.allowedContactDomains",
             "essentialcontacts.managed.allowedContactDomains")
    rows = []
    for name in names:
        row = {"constraint": name, "name": "projects/1/policies/" + name}
        key = name.replace(".", "_")
        if key in rules:
            row["spec"] = {"rules": rules[key]}
        rows.append({"data": row})
    return {"collections": {"org_policy_effective": [{"scope": "projects/p", "status": "collected"}]}, "org_policy_effective": rows}


_PROJECT = {"name": "projects/1", "projectId": "p"}
_ON = [{"enforce": True}]
_OFF = [{"enforce": False}]
CASES["gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked"] = {
    "pass": _PROJECT, "pass_index": _orgpol_index(iam_managed_disableServiceAccountKeyCreation=_ON, iam_disableServiceAccountKeyUpload=_ON),
    "fail": _PROJECT, "fail_index": _orgpol_index(iam_disableServiceAccountKeyCreation=_ON, iam_managed_disableServiceAccountKeyCreation=_OFF,
                                                  iam_disableServiceAccountKeyUpload=_ON),
    "index": _orgpol_index(), "missing": {"projectId": "p"}, "malformed": {"name": 5}}
CASES["gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled"] = {
    "pass": _PROJECT, "pass_index": _orgpol_index(iam_disableCrossProjectServiceAccountUsage=_ON),
    "fail": _PROJECT, "fail_index": _orgpol_index(iam_disableCrossProjectServiceAccountUsage=_OFF),
    "index": _orgpol_index(), "missing": {"projectId": "p"}, "malformed": {"name": 5}}
CASES["gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled"] = {
    "pass": _PROJECT, "pass_index": _orgpol_index(iam_automaticIamGrantsForDefaultServiceAccounts=_ON),
    "fail": _PROJECT, "fail_index": _orgpol_index(),
    "index": _orgpol_index(), "missing": {"projectId": "p"}, "malformed": {"name": 5}}
CASES["gcp.htbp.orgpolicy.domain_restricted_sharing"] = {
    "pass": _PROJECT, "pass_index": _orgpol_index(iam_allowedPolicyMemberDomains=[{"values": {"allowedValues": ["C0abc123"]}}]),
    "fail": _PROJECT, "fail_index": _orgpol_index(iam_allowedPolicyMemberDomains=[{"allowAll": True}]),
    "index": _orgpol_index(), "missing": {"projectId": "p"}, "malformed": {"name": 5}}
CASES["gcp.htbp.orgpolicy.essential_contacts_domain_restricted"] = {
    "pass": _PROJECT, "pass_index": _orgpol_index(essentialcontacts_managed_allowedContactDomains=[{"enforce": True, "parameters": {"allowedDomains": ["@example.com"]}}]),
    "fail": _PROJECT, "fail_index": _orgpol_index(),
    "index": _orgpol_index(), "missing": {"projectId": "p"}, "malformed": {"name": 5}}


# ---------------------------------------------------------------- Workload Identity Federation pool-wide principal sets
POOL_WIDE = re.compile(r"^principalSet://iam\.googleapis\.com/projects/[^/]+/locations/global/workloadIdentityPools/[^/]+/\*$")
_WIF_PAGES = [GCP + "gcp-cross-project-attacks/iam-and-service-account-impersonation-attacks.md",
              GCP + "gcp-privilege-escalation/gcp-workload-identity-federation-privesc.md",
              GCP + "gcp-persistence/gcp-workload-identity-federation-persistence.md"]
_WIF_REMEDIATION = ("Bind a specific mapped identity (principal://.../subject/... or principalSet://.../attribute.repository/ORG/REPO) "
                    "instead of the pool-wide principalSet://.../workloadIdentityPools/POOL/*, and gate every provider with an "
                    "attributeCondition; otherwise any identity any current or future provider admits receives the role.")


def _pool_wide(policy):
    found = []
    for binding in list_of_objects(get(policy, "bindings", list)):
        role = get(binding, "role", str)
        members = get(binding, "members", list)
        if any(not isinstance(member, str) for member in members):
            raise Unavailable("malformed IAM binding members")
        for member in members:
            if POOL_WIDE.match(member):
                found.append({"role": role, "member": member, "conditional": "condition" in binding})
    return found


@ht_register("gcp.htbp.iam.sa_no_pool_wide_workload_principal_set", "gcp", "least_privilege", "service_account",
             "Service account IAM policy does not grant roles to a whole workload identity pool", "high", "AC-6", _WIF_REMEDIATION,
             pages=_WIF_PAGES)
def sa_pool_wide(item, index):
    get(item, "email", str)
    found = _pool_wide(get(item, "iamPolicy", dict))
    return result(bool(found), pool_wide_bindings=found,
                  semantics="principalSet .../workloadIdentityPools/POOL/* matches every identity any provider in the pool admits")


@ht_register("gcp.htbp.iam.policy_no_pool_wide_workload_principal_set", "gcp", "least_privilege", "iam_policy",
             "Project/folder/organization IAM policy does not grant roles to a whole workload identity pool", "high", "AC-6",
             _WIF_REMEDIATION, pages=_WIF_PAGES)
def policy_pool_wide(item, index):
    get(item, "name", str)
    found = _pool_wide(item)
    return result(bool(found), pool_wide_bindings=found,
                  semantics="principalSet .../workloadIdentityPools/POOL/* matches every identity any provider in the pool admits")


_POOL = "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gh/"
_SA = {"email": "deploy@p.iam.gserviceaccount.com", "name": "projects/p/serviceAccounts/deploy@p.iam.gserviceaccount.com"}
CASES["gcp.htbp.iam.sa_no_pool_wide_workload_principal_set"] = {
    "pass": {**_SA, "iamPolicy": {"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": [_POOL + "attribute.repository/acme/app"]}]}},
    "fail": {**_SA, "iamPolicy": {"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": [_POOL + "*"]}]}},
    "missing": _SA, "malformed": {**_SA, "iamPolicy": {"bindings": [{"role": "r", "members": [5]}]}}}
CASES["gcp.htbp.iam.policy_no_pool_wide_workload_principal_set"] = {
    "pass": {"name": "projects/p", "bindings": [{"role": "roles/viewer", "members": ["group:ops@example.com"]}]},
    "fail": {"name": "projects/p", "bindings": [{"role": "roles/storage.admin", "members": [_POOL + "*"]}]},
    "missing": {"name": "projects/p"}, "malformed": {"name": "projects/p", "bindings": [{"role": "r", "members": "x"}]}}


# ---------------------------------------------------------------- Cloud Storage Pub/Sub notifications
TOPIC = re.compile(r"^(?://pubsub\.googleapis\.com/)?projects/([^/]+)/topics/[^/]+$")


@ht_register("gcp.htbp.storage.notification_topic_in_bucket_project", "gcp", "exposure", "bucket_notification",
             "Bucket Pub/Sub notification publishes to a topic in the bucket's own project", "medium", "SC-7",
             "Review notification configs that publish object events to topics in other projects and delete unknown ones "
             "(gcloud storage buckets notifications list/delete); each event names the object and can trigger exfiltration.",
             pages=[GCP + "gcp-persistence/gcp-storage-persistence.md"])
def bucket_notification_topic(item, index):
    get(item, "bucket", str)
    project = get(item, "bucketProject", str)
    if project.isdigit():
        raise Unavailable("bucket scope is a project number; topic projects are IDs")
    match = TOPIC.match(get(item, "topic", str))
    if not match:
        raise Unavailable("unrecognized notification topic")
    return result(match.group(1) != project, topic=item["topic"], topic_project=match.group(1), bucket_project=project,
                  semantics="Cross-project topics are a documented persistence/exfil channel; a central pipeline project may be legitimate")


_NOTE = {"name": "b/data/notificationConfigs/1", "bucket": "data", "bucketProject": "p"}
CASES["gcp.htbp.storage.notification_topic_in_bucket_project"] = {
    "pass": {**_NOTE, "topic": "//pubsub.googleapis.com/projects/p/topics/events"},
    "fail": {**_NOTE, "topic": "//pubsub.googleapis.com/projects/attacker/topics/events"},
    "missing": {"name": "b/data/notificationConfigs/1", "bucket": "data"}, "malformed": {**_NOTE, "topic": "events"}}
