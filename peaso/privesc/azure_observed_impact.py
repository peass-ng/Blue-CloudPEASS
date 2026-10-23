"""Plain impact lines for reviewed Azure privilege paths."""

import json
from pathlib import Path
import re


_IMPACT = json.loads(Path(__file__).with_suffix('.json').read_text())

_SPECIFIC_FACTS = {
    'azure-audit-microsoftwebstaticsiteslistsecretsaction':
        ('{source} has a recorded listSecrets grant on a named Static Web App.',
         'The exact Static Web App or effective listSecrets grant for {source} is missing or unresolved.'),
    'azure-apim-developer-portal-shared-token-external-principal':
        ('A recorded APIM shared token for {source} is linked to the named developer portal user.',
         'The shared token or verified portal access for {source} is missing or unresolved.'),
    'azure-authorization-elevateaccess-pim-eligible-global-admin':
        ('{source} has a recorded eligible Global Administrator role.',
         'The Global Administrator eligibility or activation path for {source} is missing or unresolved.'),
    'azure-entraid-graph-group-readwrite-all-controlled-user':
        ('{source} has a recorded Graph group-write grant and a controlled user.',
         'The Graph group-write grant or controlled user for {source} is missing or unresolved.'),
    'azure-aro-list-admin-credentials':
        ('{source} has a recorded ARO administrator credential-read grant.',
         'The ARO administrator credential-read grant or cluster for {source} is missing or unresolved.'),
    'azure-storage-local-user-create-with-sftp-access':
        ('{source} has a recorded Storage local-user creation grant on the account.',
         'The Storage local-user creation grant or SFTP container for {source} is missing or unresolved.'),
}


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
    specific = _SPECIFIC_FACTS.get(check_id)
    if specific:
        fact = (specific[1] if status == 'UNKNOWN' else specific[0]).format(source=source_label)
    if status == 'MANUAL':
        fact = _conditional_fact(fact)
    if status == 'UNKNOWN':
        if specific:
            lines = _IMPACT.get(check_id)
            if lines:
                return '\n'.join((fact,
                                  f'If the missing access facts match, {lines[0][0].lower() + lines[0][1:]}',
                                  lines[1]))
        possible = purpose if len(purpose) > 1 and purpose[1].isupper() else purpose[0].lower() + purpose[1:]
        return '\n'.join((fact,
                          f'If this path is usable, {possible}',
                          'The team cannot tell whether this identity could reach the target.'))
    lines = _IMPACT.get(check_id) if status in {'FAIL', 'MANUAL'} else None
    return '\n'.join((fact, *lines)) if lines else summary
