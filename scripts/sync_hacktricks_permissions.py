#!/usr/bin/env python3
"""Validate and synchronize the four canonical HackTricks Cloud categorization files.

No cloud credentials, network calls, or technique execution are involved.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import pprint
import re
import subprocess
import string

import yaml

PROVIDERS = ('aws', 'gcp', 'azure', 'k8s')
LEVELS = ('low', 'medium', 'high', 'critical')
SUPPLEMENT_PATH = Path('risk_rules/reviewed-permission-supplement.json')
FIELDS = {'verb', 'resource', 'subresource', 'group', 'full', 'namespace', 'name',
          'path', 'non_resource_url', 'mode', 'delegated_verb'}


def validate_match(match):
    if not isinstance(match, dict):
        raise ValueError('A match must be a mapping')
    if set(match) == {'always'} and isinstance(match['always'], bool):
        return
    for key in ('all', 'any'):
        if set(match) == {key} and isinstance(match[key], list):
            for child in match[key]:
                validate_match(child)
            return
    if set(match) == {'not'}:
        validate_match(match['not'])
        return
    if match.get('field') not in FIELDS:
        raise ValueError('Unknown Kubernetes match field')
    op = match.get('op')
    if op == 'truthy' and set(match) == {'field', 'op'}:
        return
    if set(match) != {'field', 'op', 'value'}:
        raise ValueError('Invalid match keys')
    value = match['value']
    if op in ('eq', 'ne', 'contains') and isinstance(value, str):
        return
    if op in ('prefix', 'suffix') and isinstance(value, str):
        return
    if op in ('in', 'not_in', 'prefix', 'suffix') and isinstance(value, list) and all(isinstance(v, str) for v in value):
        return
    raise ValueError('Unsupported match operation or value')


def validate(data, provider):
    if not isinstance(data, dict) or data.get('version') != 1 or data.get('provider') != provider:
        raise ValueError(f'Unsupported {provider} categorization schema')
    if provider == 'k8s':
        rules = data.get('rules')
        if not isinstance(rules, list) or not rules or rules[-1].get('match') != {'always': True}:
            raise ValueError('Kubernetes requires ordered rules and a final fallback')
        ids = set()
        for rule in rules:
            if not isinstance(rule.get('id'), str) or rule['id'] in ids:
                raise ValueError('Kubernetes rule IDs must be unique strings')
            ids.add(rule['id'])
            validate_match(rule['match'])
            if rule.get('severity') not in (*LEVELS, 'delegated'):
                raise ValueError('Invalid Kubernetes severity')
            if rule['severity'] == 'delegated':
                levels = rule.get('delegated_severities', {})
                if set(levels) != set(LEVELS) or any(v not in LEVELS for v in levels.values()):
                    raise ValueError('Invalid delegated severity map')
            if 'severity_when' in rule:
                conditional = rule['severity_when']
                validate_match(conditional['match'])
                if conditional['severity'] not in LEVELS:
                    raise ValueError('Invalid conditional severity')
            for _, field, spec, conversion in string.Formatter().parse(rule['description']):
                if field is not None and (field not in FIELDS or spec or conversion):
                    raise ValueError('Unsupported description placeholder')
        return
    categories = data.get('permission_categories', {})
    if set(categories) != set(LEVELS):
        raise ValueError('Expected all four permission categories')
    seen = {}
    for level, permissions in categories.items():
        if not isinstance(permissions, list):
            raise ValueError('Categories must contain permission lists')
        for permission in permissions:
            if not isinstance(permission, str) or not permission.strip():
                raise ValueError('Permissions must be nonempty strings')
            normalized = permission.casefold() if provider in ('aws', 'azure') else permission
            if normalized in seen and seen[normalized] != level:
                raise ValueError(f'Duplicate permission: {permission}')
            seen[normalized] = level
    for permission, level in data.get('severity_overrides', {}).items():
        normalized = permission.casefold() if provider in ('aws', 'azure') else permission
        if level not in LEVELS or (normalized in seen and seen[normalized] != level):
            raise ValueError(f'Override and category disagree: {permission}')
    for level in ('critical', 'high'):
        combinations = data.get('combinations', {}).get(level)
        if not isinstance(combinations, list):
            raise ValueError('Missing permission combinations')
        for combo in combinations:
            if not isinstance(combo, list) or not combo or any(not isinstance(p, str) or not p.strip() for p in combo):
                raise ValueError('Invalid permission combination')
    for key, values in data.items():
        if key.endswith('_regex'):
            for expression in (values if isinstance(values, list) else [values]):
                re.compile(expression)


def normalize(provider, permission):
    return permission.casefold() if provider in ('aws', 'azure') else permission


def _unique_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate supplement JSON key: {key}')
        result[key] = value
    return result


def load_supplement(path):
    """Accept reviewed exact ratings only, never patterns or executable rules."""
    content = path.read_bytes()
    supplement = json.loads(content, object_pairs_hook=_unique_json_keys)
    required = {'version', 'review', 'providers'}
    if (not isinstance(supplement, dict) or not required <= set(supplement)
            or not set(supplement) <= required | {'non_permission_identifiers'}
            or type(supplement['version']) is not int or supplement['version'] != 1):
        raise ValueError('Unsupported permission supplement schema')
    review = supplement['review']
    if not isinstance(review, dict) or set(review) != {'description', 'baseline_archive', 'provider_sha256'}:
        raise ValueError('Supplement requires explicit review provenance')
    archive = review['baseline_archive']
    if not isinstance(review['description'], str) or not review['description'].strip():
        raise ValueError('Invalid supplement review provenance')
    if (not isinstance(archive, dict) or set(archive) != {'name', 'sha256'}
            or not isinstance(archive['name'], str)
            or not re.fullmatch(r'[A-Za-z0-9_.-]+\.zip', archive['name'])
            or not isinstance(archive['sha256'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', archive['sha256'])):
        raise ValueError('Invalid supplement review provenance')
    providers = supplement['providers']
    if not isinstance(providers, dict) or not providers or not set(providers) <= set(PROVIDERS[:3]):
        raise ValueError('Unsupported supplement providers')
    receipts = review['provider_sha256']
    if not isinstance(receipts, dict) or set(receipts) != set(providers):
        raise ValueError('Supplement requires per-provider review hashes')
    patterns = {
        'aws': r'[A-Za-z0-9-]+:[A-Za-z0-9]+',
        'gcp': r'[A-Za-z0-9_-]+(?:[./][A-Za-z0-9_-]+)+',
        'azure': r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+',
    }
    identifiers = supplement.get('non_permission_identifiers', {})
    if not isinstance(identifiers, dict) or not set(identifiers) <= set(providers):
        raise ValueError('Unsupported supplement non-permission providers')
    for provider, categories in providers.items():
        receipt = receipts[provider]
        if (not isinstance(receipt, dict) or set(receipt) != {'baseline', 'reviewed'}
                or any(not isinstance(v, str) or not re.fullmatch(r'[a-f0-9]{64}', v)
                       for v in receipt.values())):
            raise ValueError('Invalid supplement review hashes')
        if not isinstance(categories, dict) or set(categories) != set(LEVELS):
            raise ValueError('Supplement requires all four permission categories')
        seen, exact = {}, set()
        for level in LEVELS:
            values = categories[level]
            if not isinstance(values, list):
                raise ValueError('Supplement categories must contain permission lists')
            for permission in values:
                if not isinstance(permission, str) or not re.fullmatch(patterns[provider], permission):
                    raise ValueError('Supplement permissions must be exact provider permissions')
                normalized = normalize(provider, permission)
                if permission in exact or (normalized in seen and seen[normalized] != level):
                    raise ValueError(f'Duplicate or conflicting supplement permission: {permission}')
                seen[normalized] = level
                exact.add(permission)
        values = identifiers.get(provider, [])
        if not isinstance(values, list):
            raise ValueError('Supplement non-permission identifiers must be lists')
        identifier_seen = set()
        for identifier in values:
            if not isinstance(identifier, str) or not re.fullmatch(patterns[provider], identifier):
                raise ValueError('Supplement non-permission identifiers must be exact identifiers')
            normalized = normalize(provider, identifier)
            if normalized in seen or normalized in identifier_seen:
                raise ValueError('Conflicting or duplicate supplement non-permission identifier')
            identifier_seen.add(normalized)
    return supplement, content


def merge_supplement(data, contents, supplement):
    """Canonical exact categories/overrides win, including future reclassification.

    Providers without additions keep the exact upstream bytes. Same-level case
    variants are valid; AWS/Azure comparisons alone are case insensitive.
    """
    applied, applied_identifiers = {}, {}
    for provider in PROVIDERS[:3]:
        reviewed = supplement['providers'].get(provider)
        if reviewed is None:
            continue
        canonical = data[provider]
        known = {normalize(provider, p) for values in canonical['permission_categories'].values() for p in values}
        known.update(normalize(provider, p) for p in canonical.get('severity_overrides', {}))
        identifiers = {normalize(provider, p) for p in canonical.get('non_permission_identifiers', [])}
        additions = {level: sorted(p for p in reviewed[level] if normalize(provider, p) not in known) for level in LEVELS}
        if any(normalize(provider, p) in identifiers for values in additions.values() for p in values):
            raise ValueError(f'Supplement conflicts with canonical non-permission identifiers: {provider}')
        applied[provider] = additions
        identifier_additions = sorted(p for p in supplement.get('non_permission_identifiers', {}).get(provider, [])
                                      if normalize(provider, p) not in known | identifiers)
        applied_identifiers[provider] = identifier_additions
        if any(additions.values()) or identifier_additions:
            effective = copy.deepcopy(canonical)
            if any(additions.values()):
                effective['permission_categories'] = {
                    level: sorted(canonical['permission_categories'][level] + additions[level]) for level in LEVELS}
            if identifier_additions:
                effective['non_permission_identifiers'] = canonical.get('non_permission_identifiers', []) + identifier_additions
            validate(effective, provider)
            data[provider] = effective
            contents[provider] = yaml.safe_dump(effective, sort_keys=False, width=120).encode()
    return applied, applied_identifiers


def sync(book_root: Path, target: Path, *, check=False, validate_only=False, supplement_path=None):
    source = book_root / 'src/permission-categorizations'
    contents = {p: (source / f'{p}.yaml').read_bytes() for p in PROVIDERS}
    data = {p: yaml.safe_load(contents[p]) for p in PROVIDERS}
    for provider in PROVIDERS:
        validate(data[provider], provider)
    canonical_hashes = {f'{p}.yaml': hashlib.sha256(contents[p]).hexdigest() for p in PROVIDERS}
    explicit_supplement = supplement_path is not None
    supplement_path = Path(supplement_path) if explicit_supplement else target / SUPPLEMENT_PATH
    supplement = None
    if explicit_supplement or supplement_path.exists():
        supplement, supplement_bytes = load_supplement(supplement_path)
        applied, applied_identifiers = merge_supplement(data, contents, supplement)
    if validate_only:
        return
    cloud = (target / 'src/CloudPEASS/permission_risk_classifier.py').is_file()
    if not cloud and not (target / 'scripts/cloud_permission_risks.py').is_file():
        raise ValueError('Target must be CloudPEASS or Blue-CloudPEASS')
    rules_dir = target / ('src/CloudPEASS/risk_rules' if cloud else 'risk_rules')
    outputs = {rules_dir / f'{p}.yaml': contents[p] for p in PROVIDERS}
    for provider in PROVIDERS[:3]:
        if cloud:
            path = target / f'src/sensitive_permissions/{provider}.py'
            original = path.read_text()
            lines = original.splitlines(keepends=True)
            replacements = []
            names = {'very_sensitive_combinations': 'critical', 'sensitive_combinations': 'high'}
            for node in ast.parse(original).body:
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names:
                    name = node.targets[0].id
                    replacements.append((node.lineno - 1, node.end_lineno,
                                         name + ' = ' + pprint.pformat(data[provider]['combinations'][names[name]], width=100) + '\n'))
            if len(replacements) != 2:
                raise ValueError(f'Missing legacy combination assignments: {path}')
            # Keep existing formatting when the literal value has not changed.
            for start, end, text in sorted(replacements, reverse=True):
                old = ast.literal_eval(ast.parse(''.join(lines[start:end])).body[0].value)
                level = names[ast.parse(text).body[0].targets[0].id]
                if old != data[provider]['combinations'][level]:
                    lines[start:end] = [text]
            outputs[path] = ''.join(lines).encode()
        else:
            outputs[target / f'{provider}_permissions_cat.yaml'] = yaml.safe_dump(
                data[provider]['permission_categories'], sort_keys=False, width=120).encode()
    hashes = {f'{p}.yaml': hashlib.sha256(contents[p]).hexdigest() for p in PROVIDERS}
    manifest_path = rules_dir / 'hacktricks-source.json'
    prior = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    prior_canonical_hashes = prior.get('canonical_sha256', prior.get('sha256'))
    if prior_canonical_hashes == canonical_hashes:
        manifest = prior  # Unrelated book commits must not create update commits.
    else:
        revision = subprocess.check_output(['git', '-C', str(book_root), 'rev-parse', 'HEAD'], text=True).strip()
        manifest = dict(repository='HackTricks-wiki/hacktricks-cloud', revision=revision,
                        path='src/permission-categorizations', sha256=hashes)
    if supplement is not None:
        # Keep legacy sha256 as bundled hashes for existing consumers. The
        # upstream revision describes canonical_sha256, never local additions.
        try:
            supplement_name = supplement_path.resolve().relative_to(target.resolve()).as_posix()
        except ValueError:
            supplement_name = supplement_path.name
        manifest = dict(repository=manifest['repository'], revision=manifest['revision'],
                        path=manifest['path'], sha256=hashes,
                        sha256_scope='effective-bundled-files', canonical_sha256=canonical_hashes,
                        supplement=dict(path=supplement_name,
                                        sha256=hashlib.sha256(supplement_bytes).hexdigest(),
                                        review=supplement['review']),
                        effective=dict(merge_policy='canonical-first-missing-exact-v1',
                                       supplement_permissions=applied,
                                       supplement_non_permission_identifiers=applied_identifiers))
    elif 'supplement' in manifest:
        manifest = dict(repository=manifest['repository'], revision=manifest['revision'],
                        path=manifest['path'], sha256=hashes)
    outputs[manifest_path] = (json.dumps(manifest, indent=2) + '\n').encode()
    stale = [path for path, content in outputs.items() if not path.exists() or path.read_bytes() != content]
    if check and stale:
        raise ValueError('Stale canonical permissions: ' + ', '.join(str(p.relative_to(target)) for p in stale))
    if not check:
        for path in stale:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(outputs[path])
    print(f'{len(stale)} files {"need synchronization" if check else "updated"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--book-root', type=Path, required=True)
    parser.add_argument('--target-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--supplement', type=Path,
                        help='Reviewed exact-permission supplement (required to exist when specified; default: optional target risk_rules/reviewed-permission-supplement.json)')
    args = parser.parse_args()
    sync(args.book_root, args.target_root, check=args.check, validate_only=args.validate_only,
         supplement_path=args.supplement)


if __name__ == '__main__':
    main()
