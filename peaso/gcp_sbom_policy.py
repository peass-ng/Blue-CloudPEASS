"""Bounded owner workload scope for native Cloud Run SBOM collection.

This declaration cannot contain observations, endpoints, or image evidence.
Intake can validate the declared project. Only collection receives the actual
selected scopes and can enforce their equality to that declaration.
"""
import re

OPTION = 'sw52'
FIELDS = {'status', 'scope', 'sbomCloudRunServices'}
PROJECT = r'projects/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
REGION = r'[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?'
SERVICE = r'[a-z](?:[a-z0-9-]{0,47}[a-z0-9])?'


def normalize(value, scopes=None):
    if not isinstance(value, dict) or set(value) != FIELDS or value.get('status') != 'collected':
        raise ValueError('SBOM scope requires an exact owner workload declaration')
    scope = value.get('scope')
    if not isinstance(scope, str) or not re.fullmatch(PROJECT, scope):
        raise ValueError('SBOM scope must name one project')
    if scopes is not None and (not isinstance(scopes, (list, tuple)) or list(scopes) != [scope]):
        raise ValueError('SBOM review must equal the actual selected project scope')
    services = value.get('sbomCloudRunServices')
    if not isinstance(services, list) or not 1 <= len(services) <= 1000:
        raise ValueError('SBOM scope requires between 1 and 1000 Cloud Run services')
    pattern = re.escape(scope) + '/locations/' + REGION + '/services/' + SERVICE
    if any(not isinstance(name, str) or not re.fullmatch(pattern, name) for name in services):
        raise ValueError('SBOM services must be literal resource IDs in the declared project')
    if len(set(services)) != len(services):
        raise ValueError('SBOM workload scope contains duplicate services')
    return {'status': 'collected', 'scope': scope, 'sbomCloudRunServices': list(services)}
