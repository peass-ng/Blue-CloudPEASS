"""Safe metadata projections for two configuration-only Azure successors.

Only called after a real, unmasked ARM resource GET. This module performs no
requests and does not assert key authorization, availability or cryptographic use.
"""
from copy import deepcopy
import re

CONTRACTS = {
    'log_analytics_cluster': ('Microsoft.OperationalInsights/clusters', '2023-09-01'),
    'stream_analytics_job': ('Microsoft.StreamAnalytics/streamingjobs', '2020-03-01'),
}


def metadata_detail(value, kind, scope, version):
    """Bind the GET identity and preserve only the documented metadata fields."""
    if kind not in CONTRACTS:
        return value
    native_type, expected_version = CONTRACTS[kind]
    segment = r'[^/?#%\\\s]+'
    rid = value.get('id') if isinstance(value, dict) else None
    if (version != expected_version or not isinstance(rid, str)
            or re.fullmatch(re.escape(scope) + '/resourceGroups/' + segment + '/providers/'
                            + re.escape(native_type) + '/' + segment, rid, re.I) is None
            or any(part in ('.', '..') for part in rid.split('/'))
            or str(value.get('type', '')).casefold() != native_type.casefold()
            or not isinstance(value.get('name'), str)
            or value['name'].casefold() != rid.rsplit('/', 1)[-1].casefold()
            or not isinstance(value.get('properties'), dict)):
        raise ValueError('foreign or malformed native CMK configuration resource')
    if kind == 'log_analytics_cluster':
        # This resource's entire ARM GET is metadata. Preserve its established
        # full representation for the independent double-encryption consumer.
        selected = deepcopy(value)
        selected['_provenance'] = {**selected.get('_provenance', {}),
            'source_operation': 'get', 'read_only': True, 'api_version': version,
            'request_path': rid, 'representation': 'full'}
        return selected
    selected = {key: deepcopy(value[key]) for key in ('id', 'name', 'type', 'location', 'sku') if key in value}
    fields = ('contentStoragePolicy', 'jobStorageAccount', 'jobType', 'jobId', 'jobState', 'provisioningState')
    properties = {key: deepcopy(value['properties'][key]) for key in fields if key in value['properties']}
    if kind == 'stream_analytics_job' and isinstance(properties.get('jobStorageAccount'), dict):
        # The same GET may contain accountKey, input credentials or query text.
        # Neither the account key nor those content fields leave this boundary.
        properties['jobStorageAccount'] = {key: value for key, value in properties['jobStorageAccount'].items()
                                          if key in ('accountName', 'authenticationMode')}
    selected['properties'] = properties
    selected['_provenance'] = {'source_operation': 'get', 'read_only': True,
        'api_version': version, 'request_path': rid, 'representation': 'metadata',
        'source_representation': 'full', 'projected_property_fields': list(fields)}
    return selected
