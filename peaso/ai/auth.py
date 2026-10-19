"""Encrypted personal Codex sign-in and an explicitly configured platform token.

Device protocol mirrors codex-rs/login/src/device_code_auth.rs. Never accepts
an issuer, verification URL or OAuth client supplied by a browser.
"""
import base64
import json
import os
import time
import uuid
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from fastapi import Depends, HTTPException, Response

ISSUER = "https://auth.openai.com"
CLIENT = "app_EMoamEEZ73f0CkXaXp7hrann"


def claims(token):
    try:
        part = token.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
    except (ValueError, IndexError, TypeError):
        return {}


def valid(token):
    data = claims(token)
    try:
        return bool((data.get('https://api.openai.com/auth') or {}).get('chatgpt_account_id')) and float(data.get('exp') or 0) > time.time() + 120
    except (ValueError, TypeError, AttributeError):
        return False


def post(path, data, *, form=False):
    body = urlencode(data).encode() if form else json.dumps(data).encode()
    req = Request(ISSUER + path, data=body, headers={'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json'})
    try:
        with urlopen(req, timeout=20) as response:
            return response.status, json.loads(response.read(128000))
    except HTTPError as exc:
        # Do not serialize an OAuth error body or exception.
        return exc.code, {}


def default_token():
    token = os.getenv('CODEX_ACCESS_TOKEN', '')
    if valid(token):
        return token
    secret = os.getenv('CODEX_TOKEN_SECRET_ARN', '').strip()
    if secret:
        import boto3
        try:
            response = boto3.client('secretsmanager', region_name=secret.split(':')[3]).get_secret_value(SecretId=secret)
            raw = response.get('SecretString', '')
            try:
                data = json.loads(raw)
            except (ValueError, TypeError):
                data = raw
            token = data.get('access_token', '') if isinstance(data, dict) else data
            if isinstance(token, str) and valid(token):
                return token
        except Exception:
            # Provider exceptions can contain private secret identifiers.
            raise RuntimeError('codex_auth_unavailable') from None
    raise RuntimeError('codex_auth_unavailable')


def personal_token(store, cipher, user):
    raw = store.ai_state(user, 'auth') if user else None
    if raw is None:
        return default_token(), 'platform'
    data = cipher.decrypt(raw)
    if data.get('disconnected'):
        return default_token(), 'platform'
    if valid(data.get('access_token', '')):
        return data['access_token'], 'personal'
    if data.get('lock_until', 0) > time.time():
        raise RuntimeError('codex_auth_busy')
    locked = dict(data, lock_until=time.time() + 60, lock_id=uuid.uuid4().hex)
    locked_raw = cipher.encrypt(locked)
    if not store.set_ai_state(user, 'auth', locked_raw, raw):
        raise RuntimeError('codex_auth_busy')
    try:
        status, new = post('/oauth/token', {'grant_type': 'refresh_token', 'client_id': CLIENT, 'refresh_token': data['refresh_token']}, form=True)
        if status != 200 or not valid(new.get('access_token', '')):
            raise RuntimeError('codex_reconnect_required')
        data.update({key: new.get(key, data.get(key, '')) for key in ('access_token', 'refresh_token', 'id_token')})
        if not store.set_ai_state(user, 'auth', cipher.encrypt(data), locked_raw):
            raise RuntimeError('codex_auth_changed')
        return data['access_token'], 'personal'
    except Exception:
        store.set_ai_state(user, 'auth', cipher.encrypt(data), locked_raw)
        raise


def codex_available(store, identity_dir, user):
    """Resolve usable access, including refreshing a connected personal account."""
    try:
        from .crypto import AICipher
        personal_token(store, AICipher(identity_dir), user)
        return True
    except Exception:
        return False


def require_local_codex(settings, store, user):
    if settings.auth_mode == 'local' and not codex_available(store, settings.identity_dir, user):
        raise HTTPException(409, 'AI checks require a usable Codex token. Sign in with Codex in Settings, configure CODEX_ACCESS_TOKEN, or disable AI for this scan.')
    if settings.auth_mode == 'local':
        from .isolation import available
        if not available():
            raise HTTPException(409, 'AI checks require a configured isolation launcher. Configure isolated AI execution or disable AI for this scan.')


def mount_auth_routes(app, store, identity_dir, account_identity, *, auth_mode='local'):
    from .crypto import AICipher
    # Lazy so unavailable AI infrastructure cannot prevent CSPM startup.
    class Cipher:
        def encrypt(self, value):
            return AICipher(identity_dir).encrypt(value)
        def decrypt(self, value):
            return AICipher(identity_dir).decrypt(value)
    cipher = Cipher()
    if os.getenv("PEASO_STORAGE", "sqlite") == "sqlite":
        AICipher(identity_dir)  # Initialize before read-only collector/analyzer mounts use it.
    def owner(user):
        if user.auth_kind != 'user':
            raise HTTPException(403, 'Sign in with your user account')
        return user.tenant_id

    @app.get('/api/ai/codex')
    def status(user=Depends(account_identity)):
        uid = owner(user)
        raw = store.ai_state(uid, 'auth')
        connected = bool(raw and not cipher.decrypt(raw).get('disconnected'))
        platform_configured = bool(valid(os.getenv('CODEX_ACCESS_TOKEN', '')) or os.getenv('CODEX_TOKEN_SECRET_ARN'))
        available = codex_available(store, identity_dir, uid) if auth_mode == 'local' else connected or platform_configured
        from .isolation import available as isolation_available
        isolated = isolation_available()
        return {'connected': connected, 'source': 'personal' if connected else 'platform',
                'platform_configured': platform_configured, 'available': available and isolated,
                'isolation_available': isolated, 'unavailable_reason': 'ai_isolation_unavailable' if not isolated else None}

    @app.post('/api/ai/codex/login')
    def start(user=Depends(account_identity)):
        uid = owner(user)
        old = store.ai_state(uid, 'pending')
        if old and cipher.decrypt(old).get('expires_at', 0) > time.time():
            pending = cipher.decrypt(old)
            return {'verification_url': ISSUER + '/codex/device', 'user_code': pending['user_code'], 'interval': pending['interval'], 'expires_at': pending['expires_at']}
        status, data = post('/api/accounts/deviceauth/usercode', {'client_id': CLIENT})
        if status != 200:
            raise HTTPException(503, 'Codex sign-in unavailable; enable device code login in ChatGPT settings')
        pending = {'device_auth_id': data['device_auth_id'], 'user_code': data.get('user_code') or data['usercode'],
                   'interval': max(5, int(data.get('interval') or 5)), 'expires_at': time.time() + 900, 'next_poll': 0}
        if not store.set_ai_state(uid, 'pending', cipher.encrypt(pending), old):
            raise HTTPException(409, 'Sign-in already started; retry')
        return {'verification_url': ISSUER + '/codex/device', 'user_code': pending['user_code'], 'interval': pending['interval'], 'expires_at': pending['expires_at']}

    @app.post('/api/ai/codex/login/poll')
    def poll(user=Depends(account_identity)):
        uid = owner(user)
        raw = store.ai_state(uid, 'pending')
        if not raw:
            raise HTTPException(409, 'Start Codex sign-in first')
        previous_auth = store.ai_state(uid, 'auth')
        data = cipher.decrypt(raw)
        if data['expires_at'] <= time.time():
            store.set_ai_state(uid, 'pending', None, raw)
            raise HTTPException(410, 'Codex sign-in expired')
        if data.get('next_poll', 0) > time.time():
            return {'status': 'pending'}
        locked = cipher.encrypt(dict(data, next_poll=time.time() + 60))
        if not store.set_ai_state(uid, 'pending', locked, raw):
            return {'status': 'pending'}
        status, result = post('/api/accounts/deviceauth/token', {key: data[key] for key in ('device_auth_id', 'user_code')})
        if status in (403, 404):
            store.set_ai_state(uid, 'pending', cipher.encrypt(dict(data, next_poll=time.time() + data['interval'])), locked)
            return {'status': 'pending'}
        if status != 200:
            raise HTTPException(502, 'Codex sign-in failed; start again after this code expires')
        status, tokens = post('/oauth/token', {'grant_type': 'authorization_code', 'client_id': CLIENT,
            'code': result['authorization_code'], 'code_verifier': result['code_verifier'], 'redirect_uri': ISSUER + '/deviceauth/callback'}, form=True)
        if status != 200 or not valid(tokens.get('access_token', '')):
            raise HTTPException(502, 'Codex token exchange failed')
        # CAS pending first: a disconnected/cancelled login cannot reconnect later.
        if not store.set_ai_state(uid, 'pending', None, locked):
            raise HTTPException(409, 'Sign-in was cancelled')
        if not store.set_ai_state(uid, 'auth', cipher.encrypt(tokens), previous_auth):
            raise HTTPException(409, 'Codex connection changed; retry')
        return {'status': 'connected'}

    @app.delete('/api/ai/codex', status_code=204)
    def disconnect(user=Depends(account_identity)):
        uid = owner(user)
        for name in ('pending', 'auth'):
            raw = store.ai_state(uid, name)
            replacement = cipher.encrypt({'disconnected': True, 'revision': uuid.uuid4().hex}) if name == 'auth' else None
            if not store.set_ai_state(uid, name, replacement, raw):
                raise HTTPException(409, 'Codex connection is busy; retry')
        return Response(status_code=204)
