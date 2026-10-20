"""Bounded GetLaunchTemplateData reads; discard configuration before caching.

AWS documents NetworkInterfaces and AssociatePublicIpAddress as optional:
https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ResponseLaunchTemplateData.html
https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_LaunchTemplateInstanceNetworkInterfaceSpecification.html
An explicit empty list in a successful SDK response is complete for this
source predicate; an omitted list or boolean is not proof of false.
"""
from copy import deepcopy
import re

OPERATIONS = frozenset({('ec2', 'get_launch_template_data')})
READ_ACTIONS = set(OPERATIONS)
PROFILE = 'aws-launch-template-instance-network-metadata-v1'
SOURCE = 'ec2:GetLaunchTemplateData'
TAG = 'aws:ec2launchtemplate:id'


def project_response(response, service, operation, arguments, region):
    """Allowlist only native public-IP flags and request-bound completeness."""
    from .aws import ReadFailure
    identifier = arguments.get('InstanceId')
    if ((service, operation) not in OPERATIONS or not isinstance(response, dict)
            or not isinstance(identifier, str) or re.fullmatch(r'i-[a-zA-Z0-9]+', identifier) is None
            or not isinstance(region, str) or not region
            or ('InstanceId' in response and response['InstanceId'] != identifier)):
        raise ReadFailure('malformed', 'launch_template_instance_source_invalid')
    data = response.get('LaunchTemplateData')
    metadata = response.get('ResponseMetadata')
    if (not isinstance(data, dict) or not isinstance(metadata, dict)
            or type(metadata.get('HTTPStatusCode')) is not int or metadata['HTTPStatusCode'] != 200):
        raise ReadFailure('malformed', 'launch_template_instance_response_invalid')
    projected = {}
    complete = False
    if 'NetworkInterfaces' in data:
        nics = data['NetworkInterfaces']
        if not isinstance(nics, list) or any(not isinstance(nic, dict) for nic in nics):
            raise ReadFailure('malformed', 'launch_template_instance_interfaces_invalid')
        projected['NetworkInterfaces'] = []
        complete = True
        for nic in nics:
            flag = nic.get('AssociatePublicIpAddress')
            if 'AssociatePublicIpAddress' in nic and type(flag) is not bool:
                raise ReadFailure('malformed', 'launch_template_instance_public_ip_invalid')
            projected['NetworkInterfaces'].append({'AssociatePublicIpAddress': flag} if type(flag) is bool else {})
            complete = complete and type(flag) is bool
    projected.update({'InstanceId': identifier, 'collection_status': 'collected',
                      'NetworkInterfacesComplete': complete,
                      '_provenance': {'profile': PROFILE, 'source_operation': SOURCE,
                                      'region': region, 'read_only': True}})
    return {'LaunchTemplateData': projected}


def enrich(requests, session, region, items):
    """One shared-budget/cache read per tagged instance, never per template."""
    out = []
    for item in items:
        row = deepcopy(item)
        tags = row.get('Tags')
        if not isinstance(tags, list) or not any(
                isinstance(tag, dict) and tag.get('Key') == TAG
                and isinstance(tag.get('Value'), str) and tag['Value'] for tag in tags):
            out.append(row)
            continue
        # Never leave preexisting, unbound data usable after a failed read.
        row.pop('LaunchTemplateData', None)
        identifier = row.get('InstanceId')
        if not isinstance(identifier, str) or re.fullmatch(r'i-[a-zA-Z0-9]+', identifier) is None:
            row['LaunchTemplateData'] = {'collection_status': 'malformed'}
        else:
            detail = requests.detail(session, 'ec2', region, 'get_launch_template_data', InstanceId=identifier)
            if detail.get('collection_status') == 'collected' and isinstance(detail.get('LaunchTemplateData'), dict):
                row['LaunchTemplateData'] = deepcopy(detail['LaunchTemplateData'])
            else:
                row['LaunchTemplateData'] = {'collection_status': detail.get('collection_status', 'malformed')}
        out.append(row)
    return out


ENRICHERS = {'instance': enrich}
