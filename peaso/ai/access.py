"""Capture resolved cloud access, never source passwords, private keys or SDK chains.

Collector hooks share this process-local sink across collection threads. It is
only enabled by the worker for AI-enabled scans. Material is encrypted at rest.
"""
import base64
import json
import threading
import time
import uuid
from pathlib import Path

_lock = threading.Lock()
_entries = None


def begin(*, allow_live=True):
    global _entries
    with _lock:
        # A shared platform GCP identity may authorize other customers' projects.
        # target_scopes are instructions, not a Google IAM downscoping boundary.
        # Until a project-bound cloud broker exists, keep that identity entirely
        # outside shell-enabled agents; they can still review captured evidence.
        _entries = {} if allow_live else None


def peek():
    """Copy currently captured sessions without closing the collector sink."""
    from copy import deepcopy
    with _lock:
        return deepcopy(list((_entries or {}).values()))


def finish():
    global _entries
    with _lock:
        result = list((_entries or {}).values())
        _entries = None
        return result


def enabled():
    return _entries is not None


def remember(provider, scope, value):
    with _lock:
        if _entries is not None:
            key = (provider, scope, value.get('context_id', ''), value.get('tenant_id') or '')
            previous = _entries.get(key, {})
            scopes = sorted(set(previous.get('target_scopes', [])) | set(value.get('target_scopes', [])))
            endpoints = sorted(set(previous.get('endpoints', [])) | set(value.get('endpoints', [])))
            _entries[key] = dict(value, provider=provider, scope=scope, target_scopes=scopes, endpoints=endpoints,
                                 capture_policy='no_shared_platform_identity_v1')


def capture_safely(function):
    def wrapped(*args, **kwargs):
        if not enabled():
            return
        try:
            return function(*args, **kwargs)
        except Exception:
            return
    return wrapped


@capture_safely
def bearer(provider, audience, token, *, expires_at=None, context_id=None, target_scopes=(), tenant_id=None, quota_project=None, endpoints=()):
    if not enabled() or not isinstance(token, str) or not token:
        return
    try:
        part = token.split('.')[1]
        expiry = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))).get('exp')
    except (ValueError, IndexError, TypeError):
        expiry = None
    remember(provider, audience, {'format': 'bearer', 'audience': audience, 'token': token,
        'expires_at': expires_at or expiry, 'captured_at': time.time(),
        'context_id': context_id or 'selected', 'target_scopes': list(target_scopes), 'tenant_id': tenant_id,
        'quota_project': quota_project, 'endpoints': list(endpoints)})


def aws(contexts):
    if not enabled():
        return
    for session, identity in contexts:
        try:
            credential = session.get_credentials().get_frozen_credentials()
            # Convert permanent IAM user keys to an STS session. Never export them.
            if not credential.token:
                import boto3
                data = session.client('sts').get_session_token(DurationSeconds=3600)['Credentials']
                session = boto3.Session(aws_access_key_id=data['AccessKeyId'], aws_secret_access_key=data['SecretAccessKey'], aws_session_token=data['SessionToken'])
                credential = session.get_credentials().get_frozen_credentials()
                expiry = data['Expiration'].timestamp()
            else:
                expiry = None  # Frozen SDK sessions don't expose a reliable expiration.
            remember('aws', identity['Account'], {'format': 'aws-session', 'account_id': identity['Account'],
                'identity_arn': identity['Arn'], 'aws_access_key_id': credential.access_key,
                'aws_secret_access_key': credential.secret_key, 'aws_session_token': credential.token,
                'expires_at': expiry, 'captured_at': time.time()})
        except Exception:
            # Missing STS access reduces AI verification coverage, never the scan.
            continue


@capture_safely
def k8s(configuration, *, cluster_id=None, namespaces=()):
    if not enabled():
        return
    def material(path):
        return base64.b64encode(Path(path).read_bytes()).decode() if path else None
    # Resolve exec/token-file refresh before freezing the current API context.
    authorization = configuration.get_api_key_with_prefix('authorization')
    remember('k8s', configuration.host, {'format': 'kubeconfig', 'captured_at': time.time(), 'expires_at': None,
        'context_id': uuid.uuid4().hex, 'cluster_id': cluster_id,
        'namespaces': list(namespaces), 'target_scopes': list(namespaces),
        'kubeconfig': {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'scan',
            'clusters': [{'name': 'scan', 'cluster': {'server': configuration.host,
                **({'insecure-skip-tls-verify': True} if getattr(configuration, 'verify_ssl', True) is False else {}),
                **({'certificate-authority-data': material(configuration.ssl_ca_cert)} if configuration.ssl_ca_cert else {}),
                **({'tls-server-name': configuration.tls_server_name} if getattr(configuration, 'tls_server_name', None) else {})}}],
            'contexts': [{'name': 'scan', 'context': {'cluster': 'scan', 'user': 'scan'}}],
            'users': [{'name': 'scan', 'user': ({'token': authorization.removeprefix('Bearer ')} if authorization else {
                'client-certificate-data': material(configuration.cert_file), 'client-key-data': material(configuration.key_file)})}]}})


def scopes_overlap(first, second):
    return first == second or first.startswith(second.rstrip('/') + '/') or second.startswith(first.rstrip('/') + '/')


def eligible_entries(entries, snapshot):
    """Old GCP envelopes cannot prove the shared platform identity was withheld.

    This also removes derived Kubernetes tokens from old GCP scans. A rescan
    captures customer-owned credentials under the current collector policy.
    """
    if snapshot.get('provider') == 'gcp':
        return [entry for entry in entries
                if entry.get('capture_policy') == 'no_shared_platform_identity_v1']
    return entries


def bind_targets(entries, snapshot):
    """Attach selected scan targets, not a claim of effective authorization.

    Retain separate credential contexts even when their provider/audience match.
    Captured request scopes take precedence over a single-context fallback.
    """
    scopes = [scope for scope in snapshot.get('scopes', []) if isinstance(scope, str)]
    metadata = snapshot.get('metadata', {})
    contexts = {(entry.get('context_id') or 'selected', entry.get('tenant_id')) for entry in entries
                if entry.get('provider') == snapshot.get('provider')}
    single_context = len(contexts) == 1
    out = []
    for raw in entries:
        entry = dict(raw)
        provider = entry.get('provider')
        captured = entry.get('target_scopes', [])
        matched = [scope for scope in scopes if any(scopes_overlap(scope, target) for target in captured)]
        if provider == 'aws':
            account = entry.get('account_id')
            matched = [scope for scope in scopes if account and (scope == account or scope.startswith(account + '/'))]
        elif provider == 'gcp':
            if not captured and single_context:
                matched = list(scopes)
        elif provider == 'azure':
            tenant = entry.get('tenant_id')
            subscription_tenants = metadata.get('subscription_tenants', {})
            matched = []
            for scope in scopes:
                if scope.startswith('/subscriptions/'):
                    subscription = scope.split('/')[2]
                    owner = subscription_tenants.get(subscription) or subscription_tenants.get('/subscriptions/' + subscription) or metadata.get('tenant_id')
                    if (tenant and owner and tenant.lower() == owner.lower()) or (not owner and single_context):
                        matched.append(scope)
                elif scope.startswith('/tenants/'):
                    if tenant and scope.split('/')[2].lower() == tenant.lower():
                        matched.append(scope)
                elif any(scopes_overlap(scope, target) for target in captured) or single_context:
                    matched.append(scope)
            entry['subscription_ids'] = sorted({scope.split('/')[2] for scope in matched if scope.startswith('/subscriptions/')})
        elif provider == 'k8s':
            cluster = entry.get('cluster_id')
            snapshot_cluster = metadata.get('cluster_id')
            if cluster and snapshot_cluster and cluster != snapshot_cluster:
                matched = []
            elif not captured and single_context:
                matched = list(scopes)
            if cluster is None and single_context:
                entry['cluster_id'] = snapshot_cluster
            entry['namespaces'] = sorted(set(matched))
        entry['target_scopes'] = sorted(set(matched))
        out.append(entry)
    return out
