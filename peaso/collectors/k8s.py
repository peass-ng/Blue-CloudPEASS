"""Read-only Kubernetes facts through the official authenticated API client."""
from __future__ import annotations

import copy
import base64
import hashlib
import ipaddress
import os
import re
import socket
import tempfile
from itertools import count
from urllib.parse import quote, urlsplit

from peaso.snapshot import make_snapshot
from .azure import _Reader, AzureReadError, _trusted_scopes

# No Secret endpoint, log/exec/proxy subresource or mutating verb is permitted.
ENDPOINTS = {
    "role": ("/apis/rbac.authorization.k8s.io/v1/roles", True),
    "clusterrole": ("/apis/rbac.authorization.k8s.io/v1/clusterroles", False),
    "rolebinding": ("/apis/rbac.authorization.k8s.io/v1/rolebindings", True),
    "clusterrolebinding": ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", False),
    "serviceaccount": ("/api/v1/serviceaccounts", True),
    "namespace": ("/api/v1/namespaces", False),
    "pod": ("/api/v1/pods", True),
    "node": ("/api/v1/nodes", False),
    "deployment": ("/apis/apps/v1/deployments", True),
    "daemonset": ("/apis/apps/v1/daemonsets", True),
    "statefulset": ("/apis/apps/v1/statefulsets", True),
    "replicaset": ("/apis/apps/v1/replicasets", True),
    "job": ("/apis/batch/v1/jobs", True),
    "cronjob": ("/apis/batch/v1/cronjobs", True),
    "replicationcontroller": ("/api/v1/replicationcontrollers", True),
    "podtemplate": ("/api/v1/podtemplates", True),
    "service": ("/api/v1/services", True),
    "endpointslice": ("/apis/discovery.k8s.io/v1/endpointslices", True),
    "ingress": ("/apis/networking.k8s.io/v1/ingresses", True),
    "networkpolicy": ("/apis/networking.k8s.io/v1/networkpolicies", True),
    "resourcequota": ("/api/v1/resourcequotas", True),
    "limitrange": ("/api/v1/limitranges", True),
}
TYPES = tuple(ENDPOINTS) + ("network_interface", "admission_configuration", "api_discovery", "securitycontextconstraint",
                           "component_configuration", "file_metadata", "secret_metadata", "configmap_metadata", "podsecuritypolicy")

# Only configuration declarations needed for reviewed component predicates are
# preserved. Shell text, arbitrary argv and credential values remain redacted.
COMPONENTS = frozenset(("kube-apiserver", "kube-controller-manager", "kube-scheduler", "kubelet", "etcd"))
CONFIG_FLAGS = frozenset(("anonymous-auth", "profiling", "authorization-mode", "audit-log-maxage", "audit-log-maxbackup",
    "audit-log-maxsize", "audit-log-path", "etcd-cafile", "etcd-certfile", "etcd-keyfile", "kubelet-client-certificate",
    "kubelet-client-key", "kubelet-certificate-authority", "tls-cert-file", "tls-private-key-file", "client-ca-file",
    "cert-file", "key-file", "peer-cert-file", "peer-key-file", "client-cert-auth", "peer-client-cert-auth",
    "auto-tls", "peer-auto-tls", "rotate-certificates", "protect-kernel-defaults", "make-iptables-util-chains",
    "event-qps", "read-only-port", "secure-port", "insecure-port", "insecure-bind-address", "bind-address",
    "hostname-override", "kubelet-https", "use-service-account-credentials", "service-account-private-key-file",
    "root-ca-file", "service-account-key-file", "service-account-lookup", "enable-admission-plugins",
    "disable-admission-plugins", "feature-gates", "terminated-pod-gc-threshold", "tls-cipher-suites",
    "request-timeout", "streaming-connection-idle-timeout", "encryption-provider-config", "basic-auth-file", "token-auth-file"))

CONFIGURATION_PATHS = ("authentication.anonymous.enabled", "authentication.x509.clientCAFile", "authorization.mode",
    "readOnlyPort", "makeIPTablesUtilChains", "rotateCertificates", "serverTLSBootstrap", "eventRecordQPS",
    "streamingConnectionIdleTimeout", "tlsCipherSuites", "tlsCertFile", "tlsPrivateKeyFile", "protectKernelDefaults")


def _configuration_metadata(value):
    if not isinstance(value, dict):
        raise ValueError("component configuration metadata must be an object")
    output = {}
    for path in CONFIGURATION_PATHS:
        parts, current = path.split("."), value
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                break
            current = current[part]
        else:
            if isinstance(current, (dict, list)) and path != "tlsCipherSuites":
                raise ValueError("component metadata scalar is malformed")
            if path == "tlsCipherSuites" and (not isinstance(current, list) or any(not isinstance(x, str) or not x.startswith("TLS_") for x in current)):
                raise ValueError("component cipher metadata is malformed")
            if path.endswith(("File", "KeyFile")) and (not isinstance(current, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", current)):
                raise ValueError("component file metadata must be a simple absolute path")
            target = output
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = copy.deepcopy(current)
    return output


def _component_config(value):
    command, args = value.get("command"), value.get("args", [])
    if command is None:
        return None
    if not isinstance(command, list) or not isinstance(args, list) or any(not isinstance(x, str) for x in command + args):
        return {"collection_status": "malformed", "error": {"code": "invalid_component_argv"}}
    if len(command) + len(args) > 1024:
        return {"collection_status": "partial", "error": {"code": "component_argv_limit"}}
    binaries = {token.rsplit("/", 1)[-1] for token in command if not token.startswith("--")}
    selected = sorted(binaries.intersection(COMPONENTS))
    if len(selected) != 1:
        return {"component": None, "component_identification": "not_a_unique_explicit_component", "flags_complete": False}
    tokens, flags = command + args, {}
    for index, token in enumerate(tokens):
        if not token.startswith("--"):
            continue
        name, separator, captured = token[2:].partition("=")
        if name not in CONFIG_FLAGS:
            continue
        if not separator:
            captured = tokens[index + 1] if index + 1 < len(tokens) and not tokens[index + 1].startswith("--") else "true"
        # Fixed flag names, simple paths/lists/durations/enums; no URI credentials,
        # shell expressions, token payloads or multiline values cross the boundary.
        if len(captured) > 2048 or not re.fullmatch(r"[A-Za-z0-9_.,/:=+@-]*", captured) or "://" in captured:
            return {"collection_status": "malformed", "error": {"code": "unsafe_component_flag_value"}}
        if name in flags:
            return {"collection_status": "malformed", "error": {"code": "duplicate_component_flag"}}
        flags[name] = captured
    return {"component": selected[0], "flags": flags, "flags_complete": True,
            "evidence": "explicit PodSpec command/args declarations; no host or runtime configuration read"}


def validate_inline_kubeconfig(data, context=None):
    """Tenant-uploaded data cannot invoke helpers or dereference local paths."""
    import yaml
    if isinstance(data, str):
        if len(data.encode()) > 2_000_000:
            raise ValueError("inline kubeconfig exceeds size limit")
        data = yaml.safe_load(data)
    if not isinstance(data, dict):
        raise ValueError("inline kubeconfig must be an object")
    for section in ("users", "clusters", "contexts"):
        entries = data.get(section)
        if not isinstance(entries, list) or not entries or any(not isinstance(entry, dict) or not isinstance(entry.get("name"), str) for entry in entries):
            raise ValueError("malformed inline kubeconfig section")
        if len({entry["name"] for entry in entries}) != len(entries):
            raise ValueError("duplicate kubeconfig names")
    for entry in data["users"]:
        user = entry.get("user")
        if not isinstance(user, dict) or any(field in user for field in ("exec", "auth-provider", "tokenFile", "client-certificate", "client-key", "username", "password")):
            raise ValueError("inline kubeconfig cannot execute helpers or read files")
    for entry in data["clusters"]:
        cluster = entry.get("cluster")
        if not isinstance(cluster, dict) or any(field in cluster for field in ("certificate-authority", "proxy-url")) or cluster.get("insecure-skip-tls-verify"):
            raise ValueError("inline kubeconfig requires verified TLS and inline CA")
        parsed = urlsplit(cluster.get("server", ""))
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("inline kubeconfig server must use HTTPS")
    selected = context or data.get("current-context")
    match = next((entry.get("context") for entry in data["contexts"] if entry["name"] == selected), None)
    if not isinstance(match, dict):
        raise ValueError("inline kubeconfig context does not exist")
    cluster = next((entry["cluster"] for entry in data["clusters"] if entry["name"] == match.get("cluster")), None)
    user = next((entry["user"] for entry in data["users"] if entry["name"] == match.get("user")), None)
    if not isinstance(cluster, dict) or not isinstance(user, dict):
        raise ValueError("inline kubeconfig context references are invalid")
    return {"server": cluster["server"], "token": user.get("token"),
            "ca_cert_data": cluster.get("certificate-authority-data"),
            "client_cert_data": user.get("client-certificate-data"),
            "client_key_data": user.get("client-key-data"), "context": selected}


def _public_server(server):
    """Resolve and reject hosted metadata/private destinations before API access."""
    parsed = urlsplit(server)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
        raise ValueError("hosted Kubernetes server requires HTTPS")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(entry[4][0].split("%")[0]).is_global for entry in addresses):
        raise ValueError("hosted Kubernetes destination must resolve to public addresses")
    # Pin the validated address to eliminate a second DNS resolution. TLS SNI
    # and certificate hostname validation continue to use the original name.
    address = addresses[0][4][0]
    authority = "[" + address + "]" if ":" in address else address
    if parsed.port:
        authority += ":" + str(parsed.port)
    return "https://" + authority + parsed.path.rstrip("/"), parsed.hostname


class _TemporaryApi:
    def __init__(self, api, temporary):
        self.api, self.temporary = api, temporary
        self.api_client = api.api_client
        self.server = getattr(api, "server", None)

    def get_json(self, *args, **kwargs):
        return self.api.get_json(*args, **kwargs)

    def close(self):
        try:
            self.api.close()
        finally:
            self.temporary.cleanup()


class _BoundedPool:
    """SDK retries and redirects cannot bypass the collector's call budget."""
    def __init__(self, pool):
        self.pool = pool

    def request(self, method, url, **kwargs):
        if method != "GET":
            raise ValueError("native inventory transport is read-only")
        kwargs.update(redirect=False, retries=False)
        return self.pool.request(method, url, **kwargs)

    def __getattr__(self, name):
        return getattr(self.pool, name)


def _wrap_client(api_client, source_server=None):
    from bluepeass.k8s import KubernetesApi
    rest_client = getattr(api_client, "rest_client", None)
    pool = getattr(rest_client, "pool_manager", None)
    if pool is not None:
        rest_client.pool_manager = _BoundedPool(pool)
    if source_server and callable(getattr(api_client, "set_default_header", None)):
        api_client.set_default_header("Host", urlsplit(source_server).netloc)
    api = KubernetesApi(api_client)
    if source_server:
        api.server = source_server
    return api


def _new_api(auth):
    from kubernetes import client, config
    from bluepeass.k8s import KubernetesApi
    method = auth.get("method", "auto")
    if method == "inline":
        if auth.get("kubeconfig_data") is None:
            raise ValueError("inline authentication requires kubeconfig_data")
        method = "kubeconfig"
    if method not in ("auto", "kubeconfig", "context", "in_cluster", "in-cluster", "token", "certificate", "client-cert", "direct"):
        raise ValueError("unsupported Kubernetes authentication method")
    if method in ("token", "certificate", "client-cert", "direct") and not auth.get("server"):
        raise ValueError("selected direct authentication requires server")
    if method in ("auto", "kubeconfig", "context") and auth.get("kubeconfig_data") is not None:
        auth = {**auth, **validate_inline_kubeconfig(auth["kubeconfig_data"], auth.get("context"))}
    direct = None if method in ("in_cluster", "in-cluster") or (method in ("kubeconfig", "context") and auth.get("kubeconfig_data") is None) else auth.get("server")
    if direct:
        parsed = urlsplit(direct)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("direct Kubernetes server must be an HTTPS origin")
        configuration = client.Configuration()
        configuration.host = direct.rstrip("/")
        configuration.verify_ssl = True
        if auth.get("_hosted"):
            configuration.host, hostname = _public_server(direct)
            configuration.tls_server_name = hostname
            configuration.assert_hostname = hostname
        if auth.get("ca_cert"):
            configuration.ssl_ca_cert = auth["ca_cert"]
        certificate_mode = method in ("certificate", "client-cert")
        token = None if certificate_mode else auth.get("token")
        if not certificate_mode and auth.get("token_file"):
            with open(auth["token_file"], encoding="utf-8") as stream:
                token = stream.read().strip()
        if token:
            configuration.api_key = {"authorization": token}
            configuration.api_key_prefix = {"authorization": "Bearer"}
        cert, key = auth.get("client_cert"), auth.get("client_key")
        temporary = None
        inline = (("ca_cert_data", "ssl_ca_cert"), ("client_cert_data", "cert_file"), ("client_key_data", "key_file"))
        try:
            if any(auth.get(source) for source, _ in inline):
                temporary = tempfile.TemporaryDirectory(prefix="peaso-k8s-")
                for source, target in inline:
                    value = auth.get(source)
                    if value:
                        if not isinstance(value, str) or len(value) > 1_000_000:
                            raise ValueError("invalid inline TLS material")
                        payload = value.encode() if value.startswith("-----BEGIN") else base64.b64decode(value, validate=True)
                        path = os.path.join(temporary.name, source)
                        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(descriptor, "wb") as stream:
                            stream.write(payload)
                        setattr(configuration, target, path)
        except Exception:
            if temporary:
                temporary.cleanup()
            raise
        cert = cert or configuration.cert_file
        key = key or configuration.key_file
        if bool(cert) != bool(key):
            if temporary:
                temporary.cleanup()
            raise ValueError("client_cert and client_key must be supplied together")
        if cert:
            configuration.cert_file, configuration.key_file = cert, key
        if not token and not cert:
            if temporary:
                temporary.cleanup()
            raise ValueError("direct server requires token, token_file or client certificate")
        try:
            api = _wrap_client(client.ApiClient(configuration), direct)
            return _TemporaryApi(api, temporary) if temporary else api
        except Exception:
            if temporary:
                temporary.cleanup()
            raise
    elif method in ("in_cluster", "in-cluster") or (method == "auto" and (auth.get("in_cluster") or (not auth.get("kubeconfig") and not auth.get("context") and os.getenv("KUBERNETES_SERVICE_HOST")))):
        configuration = client.Configuration()
        config.load_incluster_config(client_configuration=configuration)
        api_client = client.ApiClient(configuration)
    else:
        # The official loader supports embedded certificates, current context,
        # and EKS/GKE/AKS exec credential helpers without persisting token refreshes.
        api_client = config.new_client_from_config(config_file=auth.get("kubeconfig"), context=auth.get("context"), persist_config=False)
    return _wrap_client(api_client)


def _cluster_id(api, auth):
    # Prefer provider IDs when supplied (EKS ARN/GKE full path/AKS ARM ID).
    selected = auth.get("cluster_id")
    if selected:
        return str(selected)
    configuration = getattr(getattr(api, "api_client", None), "configuration", None)
    server = getattr(api, "server", None) or getattr(configuration, "host", None) or auth.get("server")
    if not server:
        raise ValueError("cluster identity requires an API server or authoritative cluster_id")
    parsed = urlsplit(server)
    if parsed.username or not parsed.netloc:
        raise ValueError("invalid Kubernetes API origin")
    origin = parsed.scheme.lower() + "://" + parsed.netloc.lower() + parsed.path.rstrip("/")
    return "k8s-cluster:" + hashlib.sha256(origin.encode()).hexdigest()


def _sanitize(value):
    """Workload literals and last-applied annotations can carry credentials."""
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    if "command" in value or "args" in value:
        component = _component_config(value)
        if component is not None:
            result["_component_config"] = component
    for key, child in value.items():
        normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
        if (normalized_key != "automountserviceaccounttoken" and normalized_key.endswith(("password", "token", "privatekey", "clientsecret", "secretvalue"))) or normalized_key in (
            "apikey", "credentials", "stringdata", "privatekeydata"):
            continue
        if key in ("managedFields",):
            continue
        if key == "annotations" and isinstance(child, dict):
            # Retain only documented identity, networking and policy provenance.
            result[key] = {k: v for k, v in child.items() if k in (
                "eks.amazonaws.com/role-arn", "iam.gke.io/gcp-service-account",
                "azure.workload.identity/client-id", "azure.workload.identity/tenant-id",
                "k8s.v1.cni.cncf.io/networks", "k8s.v1.cni.cncf.io/network-status",
                "kubernetes.io/ingress.class", "kubernetes.io/psp", "iam.amazonaws.com/permitted",
                "iam.amazonaws.com/role", "openshift.io/scc", "openshift.io/required-scc", "kubernetes.io/service-account.name",
                "kubernetes.io/service-account.uid")}
        elif key == "env" and isinstance(child, list):
            result[key] = [{"name": entry.get("name"), **({"valueFrom": _sanitize(entry["valueFrom"])} if "valueFrom" in entry else {"value_redacted": True})} for entry in child if isinstance(entry, dict)]
        elif key in ("command", "args"):
            result[key + "_redacted"] = True
        else:
            result[key] = _sanitize(child)
    return result


def _native(item, kind, cluster, scope, namespaced):
    if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
        raise ValueError("malformed Kubernetes object")
    meta = item["metadata"]
    name, namespace = meta.get("name"), meta.get("namespace")
    if not isinstance(name, str) or not name or (namespaced and (not isinstance(namespace, str) or not namespace)):
        raise ValueError("missing Kubernetes identity")
    if namespaced and scope != "*" and namespace != scope:
        raise ValueError("object outside requested namespace")
    if not namespaced and namespace:
        raise ValueError("cluster object has namespace")
    namespace = namespace if namespaced else "_cluster"
    result = _sanitize(item)
    result["id"] = "k8s://" + "/".join(quote(str(x), safe="") for x in (cluster, kind, namespace, meta.get("uid") or name))
    result["provenance"] = {"cluster_id": cluster, "namespace": namespace, "uid": meta.get("uid"),
                            "apiVersion": item.get("apiVersion"), "resourceVersion": meta.get("resourceVersion"),
                            "evidence": "read-only list", "credential_material": "omitted"}
    return result


def _pages(reader, api, path, kind, cluster, scope, namespaced):
    continuation = None
    seen = set()
    version = None
    for page in count():
        params = {"limit": reader.page_size}
        if continuation:
            params["continue"] = continuation
        response = reader.call(api.get_json, path, params)
        if not isinstance(response, dict) or not isinstance(response.get("items"), list) or not isinstance(response.get("metadata", {}), dict):
            raise ValueError("malformed Kubernetes list")
        metadata = response.get("metadata", {})
        current_version = metadata.get("resourceVersion")
        if version is not None and current_version != version:
            raise ValueError("list resourceVersion changed across pages")
        version = current_version
        yield [_native(item, kind, cluster, scope, namespaced) for item in response["items"]]
        continuation = metadata.get("continue")
        if not continuation:
            return
        if not isinstance(continuation, str) or continuation in seen:
            raise ValueError("repeated or malformed continuation")
        seen.add(continuation)
        if reader.budget.max_pages is not None and page + 1 >= reader.budget.max_pages:
            raise AzureReadError("page_limit")


def _metadata_get(api, path, params, representation):
    """Negotiate metadata-only encodings; never add full-object JSON fallback."""
    if not hasattr(api, "api_client") or not hasattr(api.api_client, "call_api"):
        raise AzureReadError("metadata_negotiation_transport_unavailable")
    accept = "application/json;as=" + representation + ";g=meta.k8s.io;v=v1"
    try:
        response = api.api_client.call_api(path, "GET", query_params=list(params.items()),
            header_params={"Accept": accept}, auth_settings=["BearerToken"], _preload_content=False,
            _return_http_data_only=True, _request_timeout=30)
    except Exception as exc:
        raise AzureReadError("metadata_negotiation_failed", getattr(exc, "status", None)) from None
    try:
        # Kubernetes JSON encodes TypeMeta first. Reject a full SecretList before
        # consuming its object contents when a server violates negotiation.
        import json
        prefix = b""
        for _ in range(32):
            chunk = response.read(32)
            prefix += chunk
            match = re.search(rb'"kind"\s*:\s*"([^"\\]+)"', prefix)
            if match:
                if match[1].decode() != representation:
                    raise AzureReadError("metadata_representation_unsupported")
                break
            if not chunk:
                raise AzureReadError("metadata_representation_malformed")
        else:
            raise AzureReadError("metadata_representation_malformed")
        document = json.loads(prefix + response.read())
        if not isinstance(document, dict) or document.get("kind") != representation:
            raise AzureReadError("metadata_representation_malformed")
        if representation == "PartialObjectMetadataList":
            # Scrub metadata before it crosses the shared reader boundary;
            # last-applied annotations can embed the original Secret's data.
            document = _sanitize(document)
            for item in document.get("items", []):
                metadata = item.get("metadata", {}) if isinstance(item, dict) else {}
                annotations = metadata.get("annotations", {})
                if isinstance(annotations, dict):
                    metadata["annotations"] = {key: value for key, value in annotations.items() if key in (
                        "kubernetes.io/service-account.name", "kubernetes.io/service-account.uid")}
        return document
    finally:
        response.close()
        response.release_conn()


def _metadata_pages(reader, api, path, kind, cluster, scope, namespaced, *, include_type=False):
    continuation, seen, resource_version = None, set(), None
    type_catalog = {}
    for page in count():
        params = {"limit": reader.page_size}
        if continuation:
            params["continue"] = continuation
        partial = reader.call(_metadata_get, api, path, params, "PartialObjectMetadataList")
        metadata = partial.get("metadata", {})
        items = partial.get("items")
        if not isinstance(metadata, dict) or not isinstance(items, list):
            raise AzureReadError("metadata_representation_malformed")
        if resource_version is not None and metadata.get("resourceVersion") != resource_version:
            raise AzureReadError("metadata_resource_version_changed")
        resource_version = metadata.get("resourceVersion")
        for item in items:
            if not isinstance(item, dict) or set(item) - {"kind", "apiVersion", "metadata"}:
                raise AzureReadError("metadata_response_contains_full_object")
        if include_type and items:
            # Tables without row objects do not always include namespace cells.
            # Resolve types per namespace, at the partial-list resourceVersion,
            # so identical names in different namespaces cannot collide.
            namespaces = {item.get("metadata", {}).get("namespace") for item in items}
            for namespace in sorted(namespaces):
                if namespace in type_catalog:
                    continue
                if not isinstance(namespace, str):
                    raise AzureReadError("metadata_namespace_missing")
                table_path = f"/api/v1/namespaces/{quote(namespace, safe='')}/secrets"
                table_params = {"limit": reader.page_size, "includeObject": "None", "resourceVersion": resource_version,
                                "resourceVersionMatch": "Exact"}
                types, table_seen = {}, set()
                for table_page in count():
                    table = reader.call(_metadata_get, api, table_path, table_params, "Table")
                    if table.get("metadata", {}).get("resourceVersion") != resource_version:
                        raise AzureReadError("metadata_table_version_mismatch")
                    columns = table.get("columnDefinitions", [])
                    if not isinstance(columns, list) or any(not isinstance(column, dict) for column in columns):
                        raise AzureReadError("metadata_table_malformed")
                    names = [str(column.get("name", "")).lower() for column in columns]
                    if "name" not in names or "type" not in names:
                        raise AzureReadError("secret_type_metadata_unavailable")
                    for row in table.get("rows", []):
                        if not isinstance(row, dict) or row.get("object") not in (None, {}) or not isinstance(row.get("cells"), list):
                            raise AzureReadError("metadata_table_contains_object")
                        cells = row["cells"]
                        if len(cells) != len(names) or not isinstance(cells[names.index("type")], str):
                            raise AzureReadError("metadata_table_malformed")
                        types[str(cells[names.index("name")])] = cells[names.index("type")]
                    table_token = table.get("metadata", {}).get("continue")
                    if not table_token:
                        break
                    if not isinstance(table_token, str) or table_token in table_seen:
                        raise AzureReadError("metadata_table_continuation_malformed")
                    table_seen.add(table_token)
                    if reader.budget.max_pages is not None and table_page + 1 >= reader.budget.max_pages:
                        raise AzureReadError("page_limit")
                    table_params["continue"] = table_token
                type_catalog[namespace] = types
        output = []
        for item in items:
            native = _native(item, kind, cluster, scope, namespaced)
            native["provenance"]["representation"] = "PartialObjectMetadataList"
            if include_type:
                name = item["metadata"]["name"]
                types = type_catalog[item["metadata"]["namespace"]]
                if name not in types:
                    raise AzureReadError("secret_type_metadata_incomplete")
                native["type"] = types[name]
                native["provenance"]["type_source"] = "Table;includeObject=None"
            output.append(native)
        yield output
        continuation = metadata.get("continue")
        if not continuation:
            return
        if not isinstance(continuation, str) or continuation in seen:
            raise AzureReadError("metadata_continuation_malformed")
        seen.add(continuation)
        if reader.budget.max_pages is not None and page + 1 >= reader.budget.max_pages:
            raise AzureReadError("page_limit")


def collect(connector, requirements=None, *, api=None):
    options, auth = connector.get("options", {}), connector.get("auth", {})
    trusted_scopes = _trusted_scopes(options)
    requested = options.get("inventories", list(TYPES)) if requirements is None else requirements
    if not isinstance(requested, (list, tuple)) or any(kind not in TYPES for kind in requested):
        raise ValueError("unsupported Kubernetes inventory requirement")
    wanted = set(requested)
    scopes = connector.get("scopes") or ["*"]
    if not isinstance(scopes, list) or len(scopes) > 100 or any(not isinstance(x, str) or (x != "*" and (len(x) > 63 or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", x) is None)) for x in scopes):
        raise ValueError("scopes must contain at most 100 namespaces or '*'")
    scopes = ["*"] if "*" in scopes else list(dict.fromkeys(scopes))
    reader = _Reader(options)
    owned = api is None
    cluster = auth.get("cluster_id")
    try:
        if options.get("hosted"):
            if any(auth.get(field) for field in ("kubeconfig", "token_file", "ca_cert", "client_cert", "client_key", "in_cluster")) or auth.get("method") in ("in_cluster", "in-cluster"):
                raise ValueError("hosted Kubernetes requires tenant inline credentials")
            if not auth.get("server") and auth.get("kubeconfig_data") is None:
                raise ValueError("hosted Kubernetes requires an explicit API server")
            if auth.get("method") in ("kubeconfig", "context", "inline") and auth.get("kubeconfig_data") is None:
                raise ValueError("hosted kubeconfig selection requires inline material")
            auth = {**auth, "_hosted": True}
        if owned:
            api = _new_api(auth)
        cluster = _cluster_id(api, auth)
        jobs = []
        actual = wanted | ({"pod", "node"} if "network_interface" in wanted else set())
        for imported_kind in sorted(actual.intersection({"component_configuration", "file_metadata", "secret_metadata", "configmap_metadata", "podsecuritypolicy"})):
            if imported_kind in ("secret_metadata", "configmap_metadata") and imported_kind not in options.get("metadata_evidence", {}):
                plural = "secrets" if imported_kind == "secret_metadata" else "configmaps"
                for scope in scopes:
                    path = "/api/v1/" + plural if scope == "*" else f"/api/v1/namespaces/{quote(scope, safe='')}/{plural}"
                    jobs.append((imported_kind, scope, "kubernetes", lambda path=path, scope=scope, imported_kind=imported_kind:
                        _metadata_pages(reader, api, path, imported_kind, cluster, scope, True, include_type=imported_kind == "secret_metadata")))
                continue
            def supplied(imported_kind=imported_kind):
                entries = options.get("metadata_evidence", {}).get(imported_kind)
                if entries is None:
                    raise AzureReadError("manual_metadata_source_required")
                if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                    raise ValueError("metadata evidence must be an object list")
                output = []
                for index, entry in enumerate(entries):
                    if any(field in entry for field in ("data", "stringData", "contents", "private_key", "token", "password")):
                        raise ValueError("metadata evidence cannot contain values or host file contents")
                    if imported_kind == "file_metadata":
                        item = {key: entry[key] for key in ("path", "uid", "gid", "mode", "node", "platform", "_coverage") if key in entry}
                    elif imported_kind in ("secret_metadata", "configmap_metadata"):
                        item = {"metadata": _sanitize(entry.get("metadata", {}))}
                    elif imported_kind == "component_configuration":
                        if entry.get("component") not in COMPONENTS:
                            raise ValueError("component metadata subject unsupported")
                        item = {"component": entry["component"], "configuration": _configuration_metadata(entry.get("configuration", {}))}
                    else:
                        item = _sanitize(entry)
                    item["id"] = f"k8s://{quote(cluster, safe='')}/{imported_kind}/supplied-{index}"
                    item["provenance"] = {"cluster_id": cluster, "source": "operator-supplied metadata", "runtime_verified": False,
                        "namespace": item.get("metadata", {}).get("namespace", "_cluster")}
                    output.append(item)
                yield output
            jobs.append((imported_kind, scopes[0], "kubernetes", supplied))
        if actual.intersection({"api_discovery", "securitycontextconstraint"}):
            def discovery():
                document = reader.call(api.get_json, "/apis")
                groups = document.get("groups") if isinstance(document, dict) else None
                if not isinstance(groups, list) or any(not isinstance(group, dict) or not isinstance(group.get("name"), str) for group in groups):
                    raise ValueError("malformed Kubernetes API group discovery")
                yield [{"id": f"k8s://{quote(cluster, safe='')}/api-discovery", "groups": _sanitize(groups),
                    "provenance": {"cluster_id": cluster, "source": "GET /apis", "authoritative_for": "advertised API groups only"}}]
            reader.run([("api_discovery", scopes[0], "kubernetes", discovery)])
            discovered = reader.collections[-1]
            groups = {group["name"] for item in discovered["items"] for group in item["groups"]}
            if "securitycontextconstraint" in actual:
                if discovered["status"] not in ("collected", "empty"):
                    reader.collections.append({"type": "securitycontextconstraint", "scope": scopes[0], "service": "kubernetes",
                        "status": "unknown", "items": [], "error": {"code": "api_discovery_incomplete"}})
                elif "security.openshift.io" not in groups:
                    reader.collections.append({"type": "securitycontextconstraint", "scope": scopes[0], "service": "kubernetes",
                        "status": "not_collected", "coverage_status": "not_applicable", "items": [],
                        "error": {"kind": "not_applicable", "code": "openshift_api_group_absent"},
                        "applicability": {"observed_api_group_absent": "security.openshift.io", "source": "GET /apis"}})
                else:
                    jobs.append(("securitycontextconstraint", scopes[0], "kubernetes", lambda: _pages(reader, api,
                        "/apis/security.openshift.io/v1/securitycontextconstraints", "securitycontextconstraint", cluster, scopes[0], False)))
        for kind in sorted(actual.intersection(ENDPOINTS)):
            path, namespaced = ENDPOINTS[kind]
            if kind == "namespace" and scopes != ["*"]:
                for scope in scopes:
                    def namespace(scope=scope):
                        item = reader.call(api.get_json, "/api/v1/namespaces/" + quote(scope, safe=""))
                        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict) or item["metadata"].get("name") != scope:
                            raise ValueError("namespace object does not match selected scope")
                        yield [_native(item, "namespace", cluster, scope, False)]
                    jobs.append((kind, scope, "kubernetes", namespace))
                continue
            for scope in scopes if namespaced else [scopes[0]]:
                scoped_path = path
                if namespaced and scope != "*":
                    prefix, plural = path.rsplit("/", 1)
                    scoped_path = prefix + "/namespaces/" + quote(scope, safe="") + "/" + plural
                jobs.append((kind, scope, "kubernetes", lambda path=scoped_path, kind=kind, scope=scope, namespaced=namespaced: _pages(reader, api, path, kind, cluster, scope, namespaced)))
        if "admission_configuration" in wanted:
            def admission():
                for plural, kind in (("validatingwebhookconfigurations", "validatingwebhookconfiguration"), ("mutatingwebhookconfigurations", "mutatingwebhookconfiguration")):
                    yield from _pages(reader, api, "/apis/admissionregistration.k8s.io/v1/" + plural, kind, cluster, scopes[0], False)
            jobs.append(("admission_configuration", scopes[0], "kubernetes", admission))
        reader.run(jobs)
        if "network_interface" in wanted:
            for scope in scopes:
                interfaces = []
                source_statuses = []
                for collection in reader.collections:
                    if collection["type"] not in ("pod", "node") or collection["scope"] != scope:
                        continue
                    source_statuses.append(collection["status"])
                    for item in collection["items"]:
                        status = item.get("status") or {}
                        addresses = status.get("podIPs", []) if collection["type"] == "pod" else status.get("addresses", [])
                        if addresses:
                            interfaces.append({"id": item["id"] + "/observed-addresses", "resource_id": item["id"], "addresses": copy.deepcopy(addresses),
                                               "nodeName": (item.get("spec") or {}).get("nodeName"),
                                               "provenance": {"cluster_id": cluster, "source": "object.status", "authoritative_interface_inventory": False}})
                complete = source_statuses and all(s in ("collected", "empty") for s in source_statuses)
                reader.run([("network_interface", scope, "kubernetes", lambda interfaces=interfaces: iter([interfaces]))])
                if not complete:
                    reader.collections[-1].update(status="partial", error={"code": "source_inventory_incomplete"})
    except Exception as exc:
        existing = {(c["type"], c["scope"]) for c in reader.collections}
        for scope in scopes:
            for kind in sorted(wanted):
                if (kind, scope) not in existing:
                    reader.unavailable(kind, scope, "kubernetes", exc)
    finally:
        if owned and api is not None:
            api.close()
    metadata = reader.metadata()
    metadata.update(cluster_id=cluster, cluster_id_source="explicit" if auth.get("cluster_id") else "API origin digest",
                    trusted_scope_ids=trusted_scopes,
                    context=auth.get("context"), namespace_semantics="administrative scope; not a subnet",
                    network_policy_enforcement={"status": "unknown", "reason": "CNI implementation and runtime enforcement are not verified by Kubernetes policy objects"},
                    network_interfaces={"status": "observed_addresses_only", "authoritative": False},
                    usage_evidence={"status": "unknown", "reason": "No audit logs, pod logs, exec or Secret objects read"},
                    omitted_inventories=sorted(set(TYPES) - wanted))
    return make_snapshot("k8s", scopes, reader.collections, metadata=metadata)
