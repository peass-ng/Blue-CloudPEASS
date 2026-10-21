"""API taxonomy lookup without installing native evaluators.

The exact five signed aliases are build-checked against the native registrar.
This successor changes presentation metadata lookup only. It never supplies
observations, verdicts, expected contexts, or source-read authorization.
"""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from types import MappingProxyType

REGISTRY_PATH = Path(__file__).resolve().parent / 'checks/finding_types.json'
REGISTRY_SHA256 = '38086f1121219cedc9aa69ab9fe110da6ec23b0d598963b322b74bce92117f5c'
MAX_REGISTRY_BYTES = 1024 * 1024
ALIASES = MappingProxyType({
    'gcp.compute.os_login': 'gcp.ports.compute_oslogin_metadata_precedence',
    'gcp.sql.require_tls': 'gcp.ports.sql_instance_require_ssl_enabled',
    'aws_fedramp_rds_cluster_members_enhanced_monitoring': 'aws.nist.rds_cluster_member_enhanced_monitoring',
    'aws_g6_redshift_automatic_version_upgrade': 'aws.cb.redshift.allow_version_upgrade',
    'aws.pci.cloudtrail.authentication_events': 'aws.gap.cloudtrail.region_logging_management_events',
})


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate taxonomy key')
        result[key] = value
    return result


@lru_cache(maxsize=1)
def _checks():
    with REGISTRY_PATH.open('rb') as stream:
        raw = stream.read(MAX_REGISTRY_BYTES + 1)
    if (len(raw) > MAX_REGISTRY_BYTES
            or hashlib.sha256(raw).hexdigest() != REGISTRY_SHA256):
        raise ValueError('API taxonomy source identity differs')
    data = json.loads(raw, object_pairs_hook=_pairs)
    ids = [row['id'] for row in data['types']]
    checks = data['checks']
    if (data.get('schema_version') != 1 or len(ids) != len(set(ids))
            or 'unclassified' in ids or type(checks) is not dict
            or any(type(key) is not str or value not in ids for key, value in checks.items())
            or any(target not in checks or alias in checks for alias, target in ALIASES.items())):
        raise ValueError('Invalid API finding type taxonomy')
    return MappingProxyType(checks)


def type_for(check_id, category=None):
    value = _checks().get(ALIASES.get(check_id, check_id))
    return value or ('permissions' if category == 'privesc' else 'unclassified')


def install():
    from peaso import finding_types
    finding_types.type_for = type_for


SCOPE_PATH = Path(__file__).resolve().parent / 'checks/hacktricks_scope.json'
SCOPE_SHA256 = 'a989e3464e01dad58cc5e224a7bcf004da250c825751b62e96f02b3b4a069e10'


@lru_cache(maxsize=1)
def _scope():
    with SCOPE_PATH.open('rb') as stream:
        raw = stream.read(MAX_REGISTRY_BYTES + 1)
    if (len(raw) > MAX_REGISTRY_BYTES
            or hashlib.sha256(raw).hexdigest() != SCOPE_SHA256):
        raise ValueError('Checklist presentation source identity differs')
    data = json.loads(raw, object_pairs_hook=_pairs)
    if data.get('schema_version') != 1:
        raise ValueError('Unsupported HackTricks checklist review')
    for check_id, row in data['checks'].items():
        if row['decision'] not in ('include', 'exclude', 'pending') or row['group'] not in data['groups']:
            raise ValueError('Invalid HackTricks checklist decision: ' + check_id)
    return MappingProxyType({cid: row['decision'] for cid, row in data['checks'].items()})


def includes_in_hacktricks(check_id):
    return _scope().get(ALIASES.get(check_id, check_id)) == 'include'
