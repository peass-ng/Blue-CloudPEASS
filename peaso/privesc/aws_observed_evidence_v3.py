"""Three-line AWS privilege-path copy over validated modeled evidence.

Call this before the shared privilege-path fallback in finding_observation.
The existing renderer validates the exact technique, grants, target and status;
this module only changes how a validated finding is explained to people.
"""

from .finding_explanation import REVIEWED, evidence_summary as validated_summary

_FALLBACK_IMPACT = 'If misused, that access could affect data or services people rely on.'


def _short(value, fallback):
    if isinstance(value, str) and value.strip() and len(value) <= 52 and not any(c in value for c in '\n.!?'):
        return value.strip()
    return fallback


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'aws':
        return None
    cid = finding.get('check_id')
    if cid != 'admin-equivalent' and cid not in REVIEWED:
        return None
    if validated_summary(finding) is None:
        return None
    e = finding['evidence']
    source = _short(e['source'].get('label'), 'the source identity')
    targets = e['targets']
    count = e['target_count']
    if count == 1 and len(targets) == 1:
        target = _short(targets[0].get('label'), 'the target identity or resource')
    elif count > 1:
        target = f'{count} recorded targets'
    else:
        target = 'the unresolved target'
    confidence = e['confidence']
    if confidence == 'unknown':
        if cid == 'admin-equivalent':
            effect = 'If this path is usable, administrator access could allow wide changes to resources.'
            impact = 'People who rely on those resources could be affected.'
        else:
            purpose = REVIEWED[cid]['purpose']
            if not isinstance(purpose, str) or not purpose.endswith('.') or '\n' in purpose:
                return None
            conditional = ('If a usable target exists, ' if count == 0 else
                           'If the missing access details allow it, ')
            effect = conditional + purpose[0].lower() + purpose[1:]
            impact = REVIEWED[cid].get('impact', _FALLBACK_IMPACT)
            if not isinstance(impact, str) or not impact.endswith('.') or '\n' in impact:
                return None
        if count == 0:
            return '\n'.join((f'An unresolved target role or identity is missing for {source}.',
                              effect, impact))
        return '\n'.join((f'The saved access facts for {source} and {target} are incomplete.',
                          effect, impact))
    if cid == 'admin-equivalent':
        if confidence == 'conditional':
            return '\n'.join((f'The recorded grants may give {source} administrator access to {target}.',
                              'This could allow wide changes to resources in that scope.',
                              'People who rely on those resources could be affected.'))
        return '\n'.join((f'The recorded grants give {source} administrator access to {target}.',
                          'This access can change many resources in that scope.',
                          'People who rely on those resources could be affected.'))
    purpose = REVIEWED[cid]['purpose']
    if not isinstance(purpose, str) or not purpose.endswith('.') or '\n' in purpose:
        return None
    impact = REVIEWED[cid].get('impact', _FALLBACK_IMPACT)
    if not isinstance(impact, str) or not impact.endswith('.') or '\n' in impact:
        return None
    first = (f'The saved grants show a path from {source} to {target}.' if confidence == 'derived' else
             f'The saved grants show a possible path from {source} to {target}.')
    return '\n'.join((first, purpose, impact))
