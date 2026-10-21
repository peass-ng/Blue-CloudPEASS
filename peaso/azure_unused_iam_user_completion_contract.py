"""Shared metadata contract for successful Entra user sign-in observations."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from urllib.parse import parse_qsl, urlsplit

from peaso.azure_unused_iam_contract import guid

KIND = 'azure_unused_iam_user_success_evidence'
SCHEMA = 'azure-unused-user-success-v1'
GRAPH = 'https://graph.microsoft.com'
ENDPOINT = '/v1.0/users?$select=id,displayName,accountEnabled,createdDateTime,signInActivity'
SELECT = 'id,displayName,accountEnabled,createdDateTime,signInActivity'
MAX_ROWS = 100000


def digest(items):
    return sha256(json.dumps(items, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def validate_read(url, *, audience, body):
    parsed = urlsplit(url)
    if (audience != GRAPH or body is not None or parsed.scheme != 'https'
            or parsed.netloc != 'graph.microsoft.com' or parsed.path != '/v1.0/users'
            or parsed.fragment or parsed.username or parsed.password):
        raise ValueError('untrusted user-success continuation')
    query = parse_qsl(parsed.query, keep_blank_values=True)
    keys = [key.lower() for key, _ in query]
    if (len(keys) != len(set(keys)) or any(key not in ('$select', '$skiptoken', '$top') for key in keys)
            or dict((key.lower(), value) for key, value in query).get('$select') != SELECT
            or any(key in keys for key in ('$filter', '$search', '$orderby'))):
        raise ValueError('user-success continuation changed the full roster projection')


def project(raw):
    if not isinstance(raw, dict):
        raise ValueError('malformed Graph user')
    user_id = guid(raw.get('id'))
    row = {key: raw[key] for key in ('displayName', 'accountEnabled', 'createdDateTime', 'signInActivity') if key in raw}
    row['id'] = user_id
    if any(key in raw for key in ('tenantId', 'tenant_id')):
        raise ValueError('user row supplied an unexpected tenant identity')
    return row
