"""Independent normative SW15 families share one subscription authority."""
import copy
from datetime import datetime, timedelta
import re

FIELDS = {'status', 'scope', 'allowAzureServices', 'maxCalls', 'maxRenewalPeriodSeconds',
          'stableCounterKeys', 'observationStart', 'observationEnd',
          'maxDaysSinceRotation', 'unusedForDays', 'approvedRotationDays'}
FUNCTION = {'maxCalls', 'maxRenewalPeriodSeconds', 'stableCounterKeys', 'observationStart', 'observationEnd'}


def normalize(options, scopes=None):
    """Return approved limits only, or None when absent; reject invented evidence."""
    def invalid():
        raise ValueError('invalid normative Azure sw15 policy')
    if 'compliance_policy' not in options:
        return None
    parent = options['compliance_policy']
    if not isinstance(parent, dict):
        invalid()
    if 'sw15' not in parent:
        return None
    raw = parent['sw15']
    if (not isinstance(raw, dict) or not set(raw) <= FIELDS
            or raw.get('status') != 'collected' or not isinstance(raw.get('scope'), str)
            or not re.fullmatch(r'/subscriptions/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', raw['scope'])):
        invalid()
    if set(raw) == {'status', 'scope'}:
        invalid()
    if scopes is not None and (len(scopes) != 1 or raw['scope'].casefold() != scopes[0].casefold()):
        invalid()
    if 'allowAzureServices' in raw and type(raw['allowAzureServices']) is not bool:
        invalid()
    for key in ('maxDaysSinceRotation', 'unusedForDays', 'approvedRotationDays'):
        if key in raw and (type(raw[key]) is not int or not 0 < raw[key] <= 36500):
            invalid()
    if FUNCTION & set(raw):
        if not FUNCTION <= set(raw):
            invalid()
        for key in ('maxCalls', 'maxRenewalPeriodSeconds'):
            if type(raw[key]) is not int or not 0 < raw[key] <= 1000000:
                invalid()
        keys = raw['stableCounterKeys']
        if (not isinstance(keys, list) or not keys or len(keys) > 32
                or any(not isinstance(k, str) or not 0 < len(k) <= 256 or any(ord(c) < 32 for c in k) for k in keys)
                or len(set(keys)) != len(keys)):
            invalid()
        try:
            start, end = (datetime.fromisoformat(raw[k].replace('Z', '+00:00')) for k in ('observationStart', 'observationEnd'))
            if any(t.tzinfo is None or t.utcoffset() != timedelta(0) for t in (start, end)) or not 0 < (end-start).total_seconds() <= 90*86400:
                invalid()
        except (ValueError, TypeError, AttributeError):
            invalid()
    return copy.deepcopy(raw)
