"""Conservative scheduling eligibility; credential contents never leave this module.

An opaque token, an absent exp claim, or a successful access check cannot prove
that a pasted credential will still work at the next scheduled occurrence.
"""
import hashlib
import json


TEMPORARY = "This connector uses temporary or unverified credentials. Run scans manually, or select renewable credentials before creating a schedule."


def scheduling_eligibility(provider, auth, *, input_mode=None, options=None, proof=None, hosted=False):
    """Return public metadata based on the authentication path actually selected."""
    auth = auth or {}
    method = auth.get("method", "")
    allowed = False
    reason = TEMPORARY
    if input_mode in {"demo", "offline_snapshot"} or (options or {}).get("demo"):
        allowed = True
    elif provider == "aws":
        if auth.get("aws_session_token") or str(auth.get("aws_access_key_id", "")).startswith("ASIA"):
            pass
        elif str(auth.get("aws_access_key_id", "")).startswith("AKIA") and auth.get("aws_secret_access_key"):
            allowed = method in {"", "access_keys", "assume_role"}
        elif method in {"assume_role", "task_role"}:
            allowed = ((hosted or method == "task_role") and not auth.get("profile")
                       and bool(auth.get("role_arn") or auth.get("assume_roles") or auth.get("role_chain")))
        elif method in {"container", "instance"}:
            allowed = True
    elif provider == "gcp":
        if auth.get("token") or auth.get("subject_token"):
            pass
        elif method in {"platform-service-account", "metadata"}:
            allowed = True
        elif auth.get("sa_json") and method in {"", "service-account", "service_account"}:
            try:
                info = auth["sa_json"]
                info = json.loads(info) if isinstance(info, str) else info
                allowed = (isinstance(info, dict) and info.get("type") == "service_account"
                           and bool(info.get("private_key")) and bool(info.get("client_email")))
            except (TypeError, ValueError):
                pass
    elif provider == "azure":
        token_fields = ("token", "arm_token", "graph_token", "vault_token", "storage_token", "logs_token", "federated_token")
        if any(auth.get(key) for key in token_fields):
            pass
        elif method == "managed-identity":
            allowed = True
        elif auth.get("tenant_id") and auth.get("client_id"):
            allowed = ((method in {"", "auto", "client-secret"} and bool(auth.get("client_secret")))
                       or (method in {"", "auto", "client-cert", "certificate"}
                           and bool(auth.get("certificate_data") or auth.get("client_certificate"))))
    elif provider == "k8s":
        if auth.get("kubeconfig_data") is not None:
            try:
                from peaso.collectors.k8s import validate_inline_kubeconfig
                selected = validate_inline_kubeconfig(auth["kubeconfig_data"], auth.get("context"))
            except (TypeError, ValueError):
                selected = {}
        else:
            selected = auth
        if selected.get("token"):
            allowed = (isinstance(proof, dict) and proof.get("kind") == "verified-k8s-legacy-token"
                       and proof.get("auth_digest") == _auth_digest(auth))
        else:
            allowed = (method == "in-cluster" or bool(selected.get("client_cert_data") and selected.get("client_key_data")))
    if allowed:
        reason = "This authentication method can be used for scheduled scans. Keep its keys or certificates valid and rotate them before expiry."
    return {"allowed": bool(allowed), "reason": reason}


def _auth_digest(auth):
    return hashlib.sha256(json.dumps(auth, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_nonexpiring_token(provider, auth, *, hosted=False):
    """Verify the sole supported non-expiring bearer type against cluster keys.

    Never trust an unsigned exp/issuer claim. Fetch keys from the configured TLS
    API server, not from JWT-supplied jku/x5u URLs. Proof stays encrypted with the
    exact connector auth and is invalidated whenever that auth changes.
    """
    if provider != "k8s":
        return None
    try:
        from peaso.collectors.k8s import validate_inline_kubeconfig
        import jwt
        selected = (validate_inline_kubeconfig(auth["kubeconfig_data"], auth.get("context"))
                    if auth.get("kubeconfig_data") is not None else auth)
        token = selected.get("token")
        if not isinstance(token, str) or len(token) > 65536:
            return None
        # This only selects candidates. Authorization comes from signature verification below.
        claims = jwt.decode(token, options={"verify_signature": False})
        required = ["iss", "sub", "kubernetes.io/serviceaccount/namespace",
                    "kubernetes.io/serviceaccount/service-account.name",
                    "kubernetes.io/serviceaccount/service-account.uid",
                    "kubernetes.io/serviceaccount/secret.name"]
        if ("exp" in claims or "aud" in claims or claims.get("iss") != "kubernetes/serviceaccount"
                or any(not isinstance(claims.get(key), str) or not claims[key] for key in required)):
            return None
        expected_subject = "system:serviceaccount:" + claims[required[2]] + ":" + claims[required[3]]
        if claims["sub"] != expected_subject:
            return None
        header = jwt.get_unverified_header(token)
        if header.get("alg") not in {"RS256", "ES256"} or not isinstance(header.get("kid"), str):
            return None
        keys = _cluster_jwks(auth, hosted=hosted).get("keys", [])
        matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == header["kid"]]
        if len(matches) != 1:
            return None
        key = jwt.PyJWK.from_dict(matches[0], algorithm=header["alg"])
        jwt.decode(token, key.key, algorithms=[header["alg"]], issuer="kubernetes/serviceaccount",
                   options={"require": required})
        return {"kind": "verified-k8s-legacy-token", "auth_digest": _auth_digest(auth)}
    except Exception:
        # Denied/unavailable JWKS and malformed credentials stay manual-only.
        return None


def _cluster_jwks(auth, *, hosted):
    """Bounded TLS GET, without adding the Kubernetes SDK to the API package."""
    import base64
    import ssl
    from urllib.parse import urlsplit
    import urllib3
    from peaso.collectors.k8s import hosted_auth, validate_inline_kubeconfig, _public_server
    selected = (hosted_auth(auth) if hosted else
                validate_inline_kubeconfig(auth["kubeconfig_data"], auth.get("context"))
                if auth.get("kubeconfig_data") is not None else auth)
    original = urlsplit(selected["server"])
    if (original.scheme != "https" or not original.hostname or original.username
            or original.password or original.query or original.fragment):
        raise ValueError("Kubernetes signing keys require a verified HTTPS API server")
    # Hosted destinations are resolved once, checked for public IPs and pinned
    # to that IP, retaining the original hostname for TLS and HTTP Host.
    destination = urlsplit(_public_server(selected["server"])[0]) if hosted else original
    hostname = selected.get("tls_server_name") or original.hostname
    ca = selected.get("ca_cert_data")
    if ca and "-----BEGIN" not in ca:
        ca = base64.b64decode(ca, validate=True).decode("ascii")
    context = ssl.create_default_context(cadata=ca or None)
    pool = urllib3.HTTPSConnectionPool(destination.hostname, port=destination.port or 443,
        ssl_context=context, assert_hostname=hostname, server_hostname=hostname,
        timeout=urllib3.Timeout(connect=5, read=10), maxsize=1, block=True)
    response = None
    try:
        response = pool.urlopen("GET", original.path.rstrip("/") + "/openid/v1/jwks",
            headers={"Authorization": "Bearer " + selected["token"], "Host": original.netloc},
            preload_content=False, redirect=False, retries=False)
        if response.status != 200:
            raise ValueError("Kubernetes signing keys unavailable")
        raw = response.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("Kubernetes signing keys exceed the response limit")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Kubernetes signing keys must be an object")
        return data
    finally:
        if response is not None:
            response.close()
            response.release_conn()
        pool.close()
