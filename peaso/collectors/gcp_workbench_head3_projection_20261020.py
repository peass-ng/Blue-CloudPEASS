"""Pure, bounded Workbench v2 upgrade-schedule projection; no reads or hooks.

Accept only the five time fields of the documented Unix-cron format. Commands,
environment assignments, macros, randomization and other extensions are outside
this supported subset. Syntax does not establish that an upgrade will execute.
"""
from copy import deepcopy
import re

KEY = 'notebook-upgrade-schedule'
MAX_SCHEDULE_BYTES = 128
_MONTHS = {name: number for number, name in enumerate(
    ('JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'), 1)}
_DAYS = {name: number for number, name in enumerate(
    ('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'))}
_FIELDS = ((0, 59, {}), (0, 23, {}), (1, 31, {}), (1, 12, _MONTHS), (0, 7, _DAYS))


def supported_schedule(value):
    """Return bounded original text or None; empty string means disabled.

    Limits deliberately define a conservative supported subset, rather than a
    claim to implement every cron dialect or Workbench's scheduling service.
    """
    if not isinstance(value, str) or len(value) > MAX_SCHEDULE_BYTES:
        return None
    if value == '':
        return ''
    if not re.fullmatch(r'[0-9A-Za-z*,/\- ]+', value, flags=re.ASCII):
        return None
    fields = value.strip(' ').split()
    if len(fields) != 5:
        return None
    for field, (low, high, names) in zip(fields, _FIELDS):
        parts = field.upper().split(',')
        if not 1 <= len(parts) <= 32:
            return None

        def number(token):
            if token in names:
                return names[token]
            if re.fullmatch(r'[0-9]{1,2}', token, flags=re.ASCII):
                result = int(token)
                if low <= result <= high:
                    return result
            return None

        for part in parts:
            pieces = part.split('/')
            if len(pieces) not in (1, 2):
                return None
            atom = pieces[0]
            if len(pieces) == 2:
                step = pieces[1]
                if (not re.fullmatch(r'[0-9]{1,2}', step, flags=re.ASCII)
                        or not 1 <= int(step) <= high - low + 1
                        or atom != '*' and '-' not in atom):
                    return None
            if atom == '*':
                continue
            bounds = atom.split('-')
            if len(bounds) == 1:
                if number(bounds[0]) is None:
                    return None
            elif len(bounds) == 2:
                start, end = number(bounds[0]), number(bounds[1])
                if start is None or end is None or start > end:
                    return None
            else:
                return None
    return value


def project_upgrade_schedule(native_metadata, projected_metadata):
    """Copy a scrubbed map, retaining only a supported native schedule scalar.

    Unsupported explicit values remain present as None with UNKNOWN coverage.
    Native denial/malformed coverage cannot be upgraded into collected coverage.
    Absence is preserved; this helper never manufactures a default or request.
    """
    if not isinstance(native_metadata, dict) or not isinstance(projected_metadata, dict):
        raise ValueError('Workbench metadata projection requires objects')
    output = deepcopy(projected_metadata)
    if KEY not in native_metadata:
        return output
    value = supported_schedule(native_metadata[KEY])
    coverage = native_metadata.get('_coverage', {})
    marker = coverage.get(KEY) if isinstance(coverage, dict) else None
    unavailable = (not isinstance(coverage, dict)
                   or KEY in coverage and (not isinstance(marker, dict)
                       or marker.get('status') not in ('collected', 'empty')
                       or marker.get('status') == 'empty' and value != ''))
    output[KEY] = None if unavailable else value
    if unavailable or value is None:
        if not isinstance(output.get('_coverage', {}), dict):
            output['_coverage'] = {}
        output.setdefault('_coverage', {})[KEY] = {
            'status': 'unknown',
            'reason': 'native_schedule_unavailable' if unavailable else 'unsupported_schedule_scalar',
        }
    return output
