"""Audit every installed AWS API output for native VPC integration metadata.

This is an independent schema discovery tool, not a cloud credentialed scan.
It deliberately scans APIs outside the application's registered inventories.
The report is evidence for review; a registered service alone does not prove
that every relevant native list, detail or network field is collected.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

NETWORK_FIELD = re.compile(r'vpc|subnet|securitygroup|networkinterface|privatelink|privateendpoint|networkconfig', re.I)


def network_paths(shape, path='', seen=(), depth=0):
    if shape is None or shape.name in seen or depth > 12:
        return []
    seen = (*seen, shape.name)
    if shape.type_name == 'structure':
        paths = []
        for key, child in shape.members.items():
            current = f'{path}.{key}'.lstrip('.')
            if NETWORK_FIELD.search(key):
                paths.append(current)
            else:
                paths.extend(network_paths(child, current, seen, depth + 1))
        return paths
    if shape.type_name == 'list':
        return network_paths(shape.member, path + '[]', seen, depth + 1)
    if shape.type_name == 'map':
        return network_paths(shape.value, path + '{}', seen, depth + 1)
    return []


def aws_report():
    import botocore
    import botocore.session
    session = botocore.session.get_session()
    services = []
    for service in session.get_available_services():
        model = session.get_service_model(service)
        operations = []
        for name in model.operation_names:
            if not name.startswith(('Describe', 'List', 'Get', 'BatchGet')):
                continue
            operation = model.operation_model(name)
            paths = network_paths(operation.output_shape)
            if paths:
                operations.append({'operation': name, 'required': list(operation.input_shape.required_members) if operation.input_shape else [],
                                   'network_paths': paths})
        if operations:
            services.append({'service': service, 'api_version': model.api_version, 'operations': operations})
    return {'sdk': 'botocore', 'sdk_version': botocore.__version__, 'services': services,
            'boundary': 'API shape candidates, including aliases, history and findings. Review all candidates; do not equate schema presence with a live VPC attachment.'}


def gcp_report(cache_dir):
    import requests
    cache_dir.mkdir(parents=True, exist_ok=True)
    directory = requests.get('https://www.googleapis.com/discovery/v1/apis', params={'preferred': 'true'}, timeout=30).json()
    def schema_paths(document, shape, path='', seen=(), depth=0):
        if depth > 12:
            return []
        if '$ref' in shape:
            ref = shape['$ref']
            if ref in seen:
                return []
            seen = (*seen, ref)
            shape = document.get('schemas', {}).get(ref, {})
        if shape.get('type') == 'array':
            return schema_paths(document, shape.get('items', {}), path + '[]', seen, depth + 1)
        result = []
        for name, value in shape.get('properties', {}).items():
            current = (path + '.' + name).lstrip('.')
            if re.search(r'network|subnet|privatelink|privateendpoint|securitygroup|serviceattachment|privateserviceconnect|^psc|enablepsc|disablepsc', name, re.I):
                result.append(current)
            else:
                result.extend(schema_paths(document, value, current, seen, depth + 1))
        return result
    def audit(row):
        name, version, url = row['name'], row['version'], row['discoveryRestUrl']
        path = cache_dir / f'{name}-{version}.json'
        try:
            if path.exists():
                document = json.loads(path.read_text())
            else:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                document = response.json()
                path.write_text(json.dumps(document))
            methods = []
            def visit(resources):
                for resource in resources.values():
                    for method in resource.get('methods', {}).values():
                        if method.get('httpMethod') != 'GET':
                            continue
                        paths = schema_paths(document, method.get('response', {}))
                        if paths:
                            methods.append({'method': method['id'], 'path': method['path'], 'network_paths': paths})
                    visit(resource.get('resources', {}))
            visit(document.get('resources', {}))
            return {'service': name, 'version': version, 'reference': url, 'operations': methods}
        except (requests.RequestException, ValueError, KeyError):
            return {'service': name, 'version': version, 'reference': url, 'status': 'discovery_unavailable'}
    with ThreadPoolExecutor(max_workers=12) as pool:
        services = list(pool.map(audit, directory['items']))
    return {'directory': 'https://www.googleapis.com/discovery/v1/apis?preferred=true',
            'api_count': len(services), 'services': [s for s in services if s.get('operations') or s.get('status')],
            'boundary': 'Public discovery schema candidates. Includes historical data, policy validation and non-Cloud products; review before treating a result as a live VPC asset.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--provider', choices=('aws', 'gcp'), default='aws')
    parser.add_argument('--cache-dir', type=Path, default=Path('/tmp/peaso-network-discovery'))
    args = parser.parse_args()
    report = json.dumps(aws_report() if args.provider == 'aws' else gcp_report(args.cache_dir), indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(report)
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
