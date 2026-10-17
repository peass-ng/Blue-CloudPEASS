"""Explicit owner scope for declared Google API PSC endpoints and DNS records."""
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

OPTION = 'gcp_psc_dns_policy'
FIELDS = {'status', 'scope', 'source_ref', 'observed_at', 'max_age_seconds', 'required_vpcs', 'required_google_api_hostnames'}


def network_identity(value):
    if not isinstance(value, str):
        raise ValueError('VPC reference must be a string')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.hostname not in ('www.googleapis.com', 'compute.googleapis.com') or
            parsed.port not in (None, 443) or parsed.username or parsed.query or parsed.fragment):
        raise ValueError('VPC reference must be a native Compute network URL')
    match = re.fullmatch(r'/compute/v1/(projects/[A-Za-z0-9_-]+)/global/networks/([a-z][a-z0-9-]{0,62})', parsed.path)
    if not match:
        raise ValueError('VPC identity is malformed')
    return match[1] + '/global/networks/' + match[2]


def instant(value):
    if not isinstance(value, str):
        raise ValueError('Policy date must be RFC3339')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Policy date must include a timezone')
    return result.astimezone(timezone.utc)


def normalize(value, scopes=None):
    if not isinstance(value, dict) or set(value) != FIELDS or value['status'] != 'approved':
        raise ValueError('PSC scope needs an exact approved owner declaration')
    scope = value['scope']
    if (not isinstance(scope, str) or not re.fullmatch(r'projects/[A-Za-z0-9_-]+', scope) or
            scopes is not None and scope not in scopes):
        raise ValueError('PSC policy must belong to a selected project')
    source = value['source_ref']
    if not isinstance(source, str) or not 1 <= len(source) <= 512 or source != source.strip():
        raise ValueError('PSC policy needs an approval reference')
    instant(value['observed_at'])
    age = value['max_age_seconds']
    if type(age) is not int or not 1 <= age <= 31536000:
        raise ValueError('PSC policy expiry must be bounded')
    networks, names = value['required_vpcs'], value['required_google_api_hostnames']
    if not isinstance(networks, list) or not 1 <= len(networks) <= 100:
        raise ValueError('PSC policy requires bounded VPC identities')
    identities = [network_identity(x) for x in networks]
    if len(set(identities)) != len(identities) or any(not x.startswith(scope + '/global/networks/') for x in identities):
        raise ValueError('PSC policy VPCs must be distinct and in its project')
    if not isinstance(names, list) or not 1 <= len(names) <= 100:
        raise ValueError('PSC policy requires bounded DNS record names')
    normalized = []
    for name in names:
        if not isinstance(name, str) or len(name) > 254:
            raise ValueError('PSC DNS name is malformed')
        name = name.lower().rstrip('.')
        base = name.removeprefix('*.')
        if (not (base == 'googleapis.com' or base.endswith('.googleapis.com')) or
                any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in base.split('.'))):
            raise ValueError('PSC DNS scope is limited to Google API names')
        normalized.append(name)
    if len(set(normalized)) != len(normalized):
        raise ValueError('PSC DNS record names must be distinct')
    return {**value, 'required_vpcs': list(networks), 'required_google_api_hostnames': normalized}
