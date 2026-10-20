"""Operator-supplied deployment identifiers, kept outside public source releases."""
import json
import os
from pathlib import Path


def configuration():
    path = os.getenv('PEASO_DEPLOY_CONFIG', '')
    if not path:
        return {}
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError('Deployment configuration must be a JSON object')
    base = Path(path).resolve().parent
    if value.get('private_identifiers_file'):
        value['private_identifiers_file'] = str((base / value['private_identifiers_file']).resolve())
    if value.get('archived_customer_role_templates'):
        value['archived_customer_role_templates'] = {
            digest: str((base / filename).resolve()) for digest, filename in value['archived_customer_role_templates'].items()
        }
    return value


def value(name):
    return os.getenv('PEASO_DEPLOY_' + name.upper(), configuration().get(name, ''))


def backend():
    raw = os.getenv('PEASO_DEPLOY_BACKEND', '')
    config = dict(json.loads(raw) if raw else configuration().get('backend', {}))
    if config and (config.get('encrypt') is not True or config.get('use_lockfile') is not True):
        raise ValueError('Deployment backend must enable encryption and locking')
    return config
