"""Plain impact lines for reviewed Azure privilege paths."""

import json
from pathlib import Path
import re


_IMPACT = json.loads(Path(__file__).with_suffix('.json').read_text())


def _conditional_fact(fact):
    match = re.fullmatch(r'The recorded grants may let (.+?) reach (.+)\.', fact)
    if match:
        return f'The recorded grants link {match.group(1)} to {match.group(2)}, with remaining conditions.'
    return fact


def format_path(check_id, status, summary, source_label):
    """Keep the saved path fact and add only an exact reviewed interpretation."""
    if not isinstance(summary, str) or not isinstance(source_label, str):
        return summary
    from .finding_explanation import REVIEWED
    if check_id == 'admin-equivalent':
        fact = re.split(r'(?<=[.!?])\s+', summary, maxsplit=1)[0]
        if status == 'MANUAL':
            fact = _conditional_fact(fact)
        lines = {
            'FAIL': ('The recorded grants may give the source administrator control.',
                     'That could let someone change many resources or read private data.'),
            'MANUAL': ('The recorded grants may give administrator control if their conditions are met.',
                       'That could let someone change many resources or read private data.'),
            'UNKNOWN': ('The record lacks facts needed to judge these administrator grants.',
                        'If these grants are usable, they may allow broad control over resources.'),
        }.get(status)
        return '\n'.join((fact, *lines)) if lines else summary
    reviewed = REVIEWED.get(check_id)
    if not reviewed or not check_id.startswith('azure-'):
        return summary
    purpose = reviewed['purpose']
    marker = ' ' + purpose
    if marker not in summary:
        return summary
    fact = summary.split(marker, 1)[0].strip()
    if not fact.endswith('.'):
        return summary
    if status == 'MANUAL':
        fact = _conditional_fact(fact)
    if status == 'UNKNOWN':
        possible = purpose if len(purpose) > 1 and purpose[1].isupper() else purpose[0].lower() + purpose[1:]
        return '\n'.join((fact,
                          f'If this path is usable, {possible}',
                          'The team cannot tell whether this identity could reach the target.'))
    lines = _IMPACT.get(check_id) if status in {'FAIL', 'MANUAL'} else None
    return '\n'.join((fact, *lines)) if lines else summary
