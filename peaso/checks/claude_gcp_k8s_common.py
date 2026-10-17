"""Shared strict helpers for the claude_gcp_k8s partition predicates.

Every helper raises ``Unavailable`` (-> UNKNOWN) on a missing, denied, malformed or
unrecognized native fact. A helper never turns absence into a FAIL unless the
absence is an explicit, complete provider inventory statement.
"""
from __future__ import annotations
from datetime import datetime, timezone
import re

from . import register, result, unknown
from .facts import get, list_of_objects, optional, complete_items, Unavailable
from .fixtures import CASES, nest

GCP_PREFIX = "gcp.claude."
K8S_PREFIX = "k8s.claude."
PREFIXES = (GCP_PREFIX, K8S_PREFIX)
CHECK_IDS = []
GCP_REMEDIATION = ("Review the declared configuration with the resource owner and apply the intended setting through "
                   "gcloud, Terraform or the console; collected metadata does not establish runtime enforcement.")
K8S_REMEDIATION = ("Review the declared Kubernetes object with its owner and apply the intended setting through the "
                   "workload manifest or admission policy; declarations do not prove runtime enforcement.")
SCOPE = "projects/p"


def _register(prefix, provider, default_remediation):
    def decorator(slug, kind, title, *, severity="medium", control="CM-6", remediation=None, category="hardening",
                  target="resource", dependencies=None):
        cid = prefix + slug
        CHECK_IDS.append(cid)
        registrar = register(cid, provider, category, kind, title, severity, control, remediation or default_remediation,
                             target=target, dependencies=list(dependencies or [kind]))

        def apply(function):
            def evaluate(item, index):
                # An object without any native field is not a collected resource: API omission defaults
                # must never turn it into PASS.
                if isinstance(item, dict) and not any(not str(key).startswith("_") and key != "collection_status" for key in item):
                    raise Unavailable("native resource has no collected fields")
                return function(item, index)
            evaluate.__name__ = function.__name__
            registrar(evaluate)
            return function
        return apply
    return decorator


gcp = _register(GCP_PREFIX, "gcp", GCP_REMEDIATION)
k8s = _register(K8S_PREFIX, "k8s", K8S_REMEDIATION)


def gid(slug):
    return GCP_PREFIX + slug


def kid(slug):
    return K8S_PREFIX + slug


def cases(cid, good, bad, **extra):
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, **extra}
    return CASES[cid]


def strings(value, what="string list"):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise Unavailable("malformed " + what)
    return value


def opt_strings(item, key):
    return strings(optional(item, key, [], list), key)


def scope_index(kind_items, scope=SCOPE):
    """Fixture builder: {kind: [items]} with complete scoped envelopes and context."""
    index = {"collections": {}, "context": {"provider": "gcp", "scope": scope, "created_at": "2026-10-10T12:00:00Z"}}
    for kind, items in kind_items.items():
        index["collections"][kind] = [{"scope": scope, "status": "collected" if items else "empty"}]
        index[kind] = [{"data": item} for item in items]
    return index


def context_scope(index):
    scope = index.get("context", {}).get("scope") if isinstance(index.get("context"), dict) else None
    if not isinstance(scope, str) or not scope:
        raise Unavailable("evaluation scope unavailable")
    return scope


def parse_time(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp unavailable")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Unavailable("malformed timestamp") from None
    if parsed.tzinfo is None:
        raise Unavailable("timestamp timezone missing")
    return parsed.astimezone(timezone.utc)


def captured_at(item, index):
    observed = None
    if isinstance(item.get("_provenance"), dict):
        observed = item["_provenance"].get("collected_at")
    if observed is None and isinstance(index.get("context"), dict):
        observed = index["context"].get("created_at")
    return parse_time(observed)


def duration_seconds(value):
    """Protobuf JSON duration ``<n>s`` -> integer seconds, else UNKNOWN."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(\.[0-9]+)?s", value):
        raise Unavailable("malformed protobuf duration")
    return int(float(value[:-1]))


# --- GCP IAM policy helpers --------------------------------------------------------------------------------

PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


def bindings(policy):
    rows = list_of_objects(get(policy, "bindings", list))
    out = []
    for row in rows:
        role = get(row, "role", str)
        members = strings(get(row, "members", list), "IAM binding members")
        out.append({"role": role, "members": members, "condition": row.get("condition")})
    return out


def root_policy(index):
    """The project/org root IAM policy (getIamPolicy) of the evaluation scope from a complete inventory."""
    scope = context_scope(index)
    roots = [p for p in complete_items(index, "iam_policy")
             if p.get("name") in (scope, "//cloudresourcemanager.googleapis.com/" + scope)]
    if len(roots) != 1:
        raise Unavailable("scope root IAM policy absent or ambiguous")
    return roots[0]


def scope_root_policy(item, index):
    scope = get(item, "scope", str)
    roots = [p for p in complete_items(index, "iam_policy")
             if p.get("name") in (scope, "//cloudresourcemanager.googleapis.com/" + scope)]
    if len(roots) != 1:
        raise Unavailable("scope root IAM policy absent or ambiguous")
    return roots[0]


def is_project_scope(item):
    scope = get(item, "scope", str)
    return scope.startswith("projects/")


def policy_case(rows, scope=SCOPE, **extra):
    policy = {"name": scope, "bindings": [{"role": r, "members": m} for r, m in rows]}
    return scope_index({"iam_policy": [policy], **extra}, scope)


# --- Firewall normalization -------------------------------------------------------------------------------

PUBLIC_SOURCES = frozenset(("0.0.0.0/0", "::0", "0.0.0.0", "::/0", "::"))
PROTOCOL_ALIASES = {"6": "tcp", "17": "udp", "132": "sctp", "1": "icmp", "58": "ipv6-icmp"}


def active_ingress(item):
    """Return None for an active INGRESS rule, or an NOT_APPLICABLE tuple."""
    direction = get(item, "direction", str)
    if direction not in ("INGRESS", "EGRESS"):
        raise Unavailable("unrecognized firewall direction")
    if direction != "INGRESS" or optional(item, "disabled", False, bool):
        return "NOT_APPLICABLE", {"reason": "Not an active ingress firewall declaration", "direction": direction}
    return None


def source_ranges(item):
    ranges = optional(item, "sourceRanges", None, list)
    if ranges is None:
        tags = opt_strings(item, "sourceTags")
        accounts = opt_strings(item, "sourceServiceAccounts")
        # GCP defaults omitted ingress source ranges to 0.0.0.0/0 only without source tags/SAs.
        ranges = [] if tags or accounts else ["0.0.0.0/0"]
    return strings(ranges, "firewall source ranges")


def is_public(item):
    return bool(set(source_ranges(item)) & PUBLIC_SOURCES)


def port_bounds(value):
    if not isinstance(value, str):
        raise Unavailable("malformed allowed port")
    parts = value.split("-")
    if len(parts) not in (1, 2) or any(not part.isdigit() for part in parts):
        raise Unavailable("malformed allowed port range")
    low, high = int(parts[0]), int(parts[-1])
    if not 0 <= low <= high <= 65535:
        raise Unavailable("invalid allowed port range")
    return low, high


def allowed_entries(item):
    """Normalized [(protocol, [(low, high)] or None for all ports)] of the allow list."""
    out = []
    for entry in list_of_objects(optional(item, "allowed", [], list)):
        protocol = get(entry, "IPProtocol", str).lower()
        protocol = PROTOCOL_ALIASES.get(protocol, protocol)
        ports = optional(entry, "ports", [], list)
        out.append((protocol, [port_bounds(p) for p in ports] if ports else None))
    return out


def exposed_ports(item, protocols, ports):
    """Allow entries that open any of ``ports`` (or every port) over ``protocols``."""
    hits = []
    for protocol, ranges in allowed_entries(item):
        if protocol != "all" and protocol not in protocols:
            continue
        if protocol == "all" or ranges is None:
            hits.append({"protocol": protocol, "ports": "all"})
            continue
        for low, high in ranges:
            if any(low <= p <= high for p in ports):
                hits.append({"protocol": protocol, "ports": f"{low}-{high}"})
    return hits


def fw(sources=None, allowed=None, direction="INGRESS", **extra):
    rule = {"name": extra.pop("name", "fw"), "direction": direction, "allowed": allowed if allowed is not None else [], **extra}
    if sources is not None:
        rule["sourceRanges"] = sources
    return rule


# --- Kubernetes PodSpec helpers --------------------------------------------------------------------------

KIND_PATHS = {"pod": "spec", "deployment": "spec.template.spec", "daemonset": "spec.template.spec",
              "statefulset": "spec.template.spec", "replicaset": "spec.template.spec",
              "replicationcontroller": "spec.template.spec", "job": "spec.template.spec",
              "cronjob": "spec.jobTemplate.spec.template.spec", "podtemplate": "template.spec"}


def pod_spec(item, kind="pod", *, include_init=False):
    spec = get(item, KIND_PATHS[kind], dict)
    containers = list(list_of_objects(get(spec, "containers", list)))
    if not containers:
        raise Unavailable("PodSpec requires at least one regular container")
    if include_init:
        for key in ("initContainers", "ephemeralContainers"):
            containers += list_of_objects(optional(spec, key, [], list))
    for container in containers:
        get(container, "name", str)
        optional(container, "securityContext", {}, dict)
    return spec, containers


def security_context(obj):
    return optional(obj, "securityContext", {}, dict)


def pod_case(*containers, kind="pod", **spec):
    return nest(KIND_PATHS[kind], {"containers": list(containers), **spec})


def container(name="c", **fields):
    return {"name": name, "image": fields.pop("image", "registry.example/app@sha256:" + "a" * 64), **fields}


__all__ = [name for name in dir() if not name.startswith("__")]
