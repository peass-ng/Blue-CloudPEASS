"""Explicit certificate-review criteria; no cloud observations are accepted."""
import copy
from datetime import datetime
import re

NAMESPACE = 'azure_tls_certificates'
AUTHORITY = {'status', 'scope', 'observed_at', 'max_age_seconds'}
PARAMETERS = {'approvedTlsServiceInventory', 'tlsObservationMaxAgeSeconds'}
SUBSCRIPTION = r'/subscriptions/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
MAX_AGE = 365 * 86400


def normalize(options):
    """Preserve supplied approval time and identity; absent criteria stay absent."""
    parent = options.get('compliance_parameters')
    if not isinstance(parent, dict) or NAMESPACE not in parent:
        return None
    raw = parent[NAMESPACE]
    def invalid():
        raise ValueError('invalid Azure TLS certificate owner criteria')
    if (not isinstance(raw, dict) or set(raw) != AUTHORITY | {'parameters'} or raw['status'] != 'collected'
            or not isinstance(raw['scope'], str) or not re.fullmatch(SUBSCRIPTION, raw['scope'])):
        invalid()
    if type(raw['max_age_seconds']) is not int or not 1 <= raw['max_age_seconds'] <= MAX_AGE:
        invalid()
    stamp = raw['observed_at']
    if not isinstance(stamp, str) or not 1 <= len(stamp) <= 64:
        invalid()
    try:
        parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            invalid()
    except (ValueError, OverflowError):
        invalid()
    parameters = raw['parameters']
    if not isinstance(parameters, dict) or set(parameters) != PARAMETERS:
        invalid()
    services = parameters['approvedTlsServiceInventory']
    if (not isinstance(services, list) or not 1 <= len(services) <= 64
            or any(not isinstance(s, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', s) for s in services)
            or len({s.casefold() for s in services}) != len(services)):
        invalid()
    age = parameters['tlsObservationMaxAgeSeconds']
    if type(age) is not int or not 1 <= age <= MAX_AGE:
        invalid()
    # The older ARM bridge lacks a supplied approval clock. Its flat SW20
    # criteria cannot share this explicit authority without rebinding time.
    applicability = options.get('compliance_parameters', {})
    arm = applicability.get('azure_arm_metadata') if isinstance(applicability, dict) else None
    if isinstance(arm, dict) and 'approvedPredefinedSslPolicyName' in arm:
        invalid()
    # Bulk-evidence enrichment subsequently merges raw and collected policies.
    # Reject a second flat authority here so that shallow merge cannot replace
    # its approval clock, scope or parameter set; namespaced families may coexist.
    legacy = options.get('compliance_policy')
    if isinstance(legacy, dict) and (AUTHORITY | {'parameters'}).intersection(legacy):
        invalid()
    return copy.deepcopy(raw)


def bind_scopes(owner, scopes):
    if owner is not None and owner['scope'].casefold() not in {s.casefold() for s in scopes}:
        raise ValueError('TLS certificate approval is outside selected subscriptions')


def merge_metadata(metadata, owner):
    """Add criteria without replacing another review's authority or parameters."""
    if owner is None:
        return
    prior = metadata.get('compliance_policy', {})
    if not isinstance(prior, dict):
        raise ValueError('ambiguous Azure owner policy')
    for key in AUTHORITY:
        if key in prior and prior[key] != owner[key]:
            raise ValueError('conflicting Azure owner approval authority')
    parameters = prior.get('parameters', {})
    if not isinstance(parameters, dict) or any(k in parameters and parameters[k] != v for k, v in owner['parameters'].items()):
        raise ValueError('conflicting Azure TLS owner criteria')
    merged = copy.deepcopy(prior)
    merged.update(copy.deepcopy(owner))
    merged['parameters'] = {**copy.deepcopy(parameters), **copy.deepcopy(owner['parameters'])}
    metadata['compliance_policy'] = merged
