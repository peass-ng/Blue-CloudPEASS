"""Plain impact lines for each reviewed Kubernetes privilege path."""

import json
from pathlib import Path
import re


_IMPACT = json.loads(Path(__file__).with_suffix('.json').read_text())


def format_path(check_id, status, summary, source_label):
    lines = _IMPACT.get(check_id, {}).get(status)
    if not lines or not isinstance(summary, str):
        return summary
    fact = re.split(r'(?<=[.!?])\s+', summary, maxsplit=1)[0]
    if status == 'MANUAL' and fact.startswith('The recorded grants may let ') and fact.endswith('.'):
        actor_target = fact.removeprefix('The recorded grants may let ').removesuffix('.')
        if ' reach ' in actor_target:
            actor, target = actor_target.split(' reach ', 1)
            fact = f'The recorded grants link {actor} to {target}, with remaining conditions.'
    if check_id == 'analysis.coverage' and fact.startswith('The scan lacks complete records for '):
        fact = 'The resource inventory is incomplete for ' + fact.removeprefix('The scan lacks complete records for ')
    if check_id in {'analysis.inactive_identity', 'analysis.network_review'} and ';' in fact:
        fact = fact.split(';', 1)[0].rstrip('. ') + '.'
    actor = source_label if isinstance(source_label, str) and len(source_label) <= 80 else 'the source identity'
    meaning, impact = (line.replace('alice', actor) for line in lines)
    return '\n'.join((fact, meaning, impact))
