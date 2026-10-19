"""Native Azure observations reviewed against exact status and evidence shapes.

Legacy identifiers and short catalog titles sometimes describe a narrower or
entirely different control. These sentences follow the actual signed predicate
and native witnesses; they never infer a result from the title or category.
"""
from __future__ import annotations
import json
import math
from pathlib import Path

ROWS = json.loads(Path(__file__).with_suffix('.json').read_text())


def _matches(value, shape):
    if 'null' in shape:
        return value is None
    if 'boolean' in shape:
        return type(value) is bool and value is shape['boolean']
    if 'integer' in shape:
        return type(value) is int and (('zero' if value == 0 else 'positive' if value > 0 else 'negative') == shape['integer'])
    if 'number' in shape:
        return type(value) in (int, float) and math.isfinite(value)
    if 'literal' in shape:
        return isinstance(value, str) and value == shape['literal']
    if 'string' in shape:
        return isinstance(value, str)
    if 'object' in shape:
        fields = shape['object']
        return isinstance(value, dict) and set(value) == set(fields) and all(_matches(value[key], sub) for key, sub in fields.items())
    if 'list' in shape:
        if not isinstance(value, list) or (not value) != shape['empty']:
            return False
        return all(any(_matches(item, sub) for sub in shape['list']) for item in value)
    return False


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'azure':
        return None
    rules = ROWS.get(finding.get('check_id', ''))
    status = finding.get('status')
    evidence = finding.get('evidence')
    if rules is None or status not in ('PASS', 'FAIL') or not isinstance(evidence, dict):
        return None
    for rule in rules:
        if status == rule['status'] and _matches(evidence, rule['evidence']):
            sentence = rule['observation']
            values = {name: evidence[field] for name, field in rule.get('values', {}).items()}
            values.update({name: len(evidence[field]) for name, field in rule.get('list_counts', {}).items()})
            if rule.get('formatter') == 'rsa_bits':
                bits = next((item.get('measured_rsa_modulus_bits') for item in evidence.get('outcomes', [])
                             if isinstance(item, dict) and item.get('status') == 'FAIL'
                             and type(item.get('measured_rsa_modulus_bits')) is int
                             and 0 < item['measured_rsa_modulus_bits'] < 2048), None)
                if bits is None:
                    continue
                values['bits'] = bits
            if values:
                sentence = sentence.format(**values)
            detail = rule.get('detail')
            if detail:
                value = evidence[detail['field']]
                if detail['kind'] == 'count':
                    phrase = f'{len(value)} {detail["label"]}'
                elif detail['kind'] == 'strings':
                    if any(not isinstance(v, str) or len(v) > 80 or any(ord(c) < 32 for c in v) for v in value):
                        return None
                    shown = ', '.join(value[:3])
                    phrase = f'{detail["label"]}: {shown}' + (f' and {len(value)-3} more' if len(value) > 3 else '')
                elif detail['kind'] == 'version':
                    phrase = f'{detail["label"]}: ' + '.'.join(map(str, value))
                else:
                    shown = ('enabled' if value else 'disabled') if type(value) is bool else value
                    phrase = f'{detail["label"]}: {shown}'
                sentence = sentence.rstrip('.') + f' ({phrase}).'
            return sentence
    return None
