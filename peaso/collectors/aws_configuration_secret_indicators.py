"""Inspect configuration values transiently and retain bounded safe indicators.

No secret bytes, value hashes, snippets, output keys or environment values are
returned. This is a corrected partial replacement for the pinned Steampipe
keyword/character-mix heuristic, not exhaustive secret discovery.
"""
from copy import deepcopy
import json
import re
from .aws_user_data_secret_indicators import project as inspect_text

SCHEMA = 'configuration-secret-indicators-v1'
CATEGORIES = {'private_key', 'cloud_credential', 'password_assignment'}
MAX_PAIRS = 256
MAX_VALUE_BYTES = 65536
MAX_TOTAL_BYTES = 1024 * 1024
_LAMBDA = re.compile(r'arn:(aws|aws-cn|aws-us-gov):lambda:([a-z0-9-]+):([0-9]{12}):function:([A-Za-z0-9_-]{1,64})(?::([A-Za-z0-9_$.-]{1,128}))?')
_STACK = re.compile(r'arn:(aws|aws-cn|aws-us-gov):cloudformation:([a-z0-9-]+):([0-9]{12}):stack/([A-Za-z][A-Za-z0-9-]{0,127})/([a-zA-Z0-9-]{1,128})')
STACK_FIELDS = ('StackName', 'StackId', 'StackStatus', 'CreationTime', 'LastUpdatedTime', 'NotificationARNs',
                'DisableRollback', 'EnableTerminationProtection', 'DriftInformation', 'ParentId', 'RootId', 'RoleARN')


def _identity(arn, name, kind):
    match = (_LAMBDA if kind == 'lambda' else _STACK).fullmatch(arn) if isinstance(arn, str) else None
    if match is None or match[4] != name:
        raise ValueError('configuration resource identity unavailable')
    partition, region, account = match.groups()[:3]
    expected = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if partition != expected or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+', region):
        raise ValueError('configuration partition or region mismatch')
    return account, region


def unavailable(status='malformed'):
    return {'Schema': SCHEMA, 'collection_status': status, 'NativeResponseComplete': False}


def _indicators(pairs, arn, name, kind, operation):
    try:
        account, region = _identity(arn, name, kind)
        if len(pairs) > MAX_PAIRS:
            raise ValueError('configuration item bound exceeded')
        values, total = {}, 0
        for key, value in pairs:
            if not isinstance(key, str) or not key or not isinstance(value, str) or key in values:
                raise ValueError('configuration pair malformed')
            size = len(key.encode('utf-8')) + len(value.encode('utf-8'))
            total += size
            if len(key) > 4096 or len(value.encode('utf-8')) > MAX_VALUE_BYTES or total > MAX_TOTAL_BYTES:
                raise ValueError('configuration byte bound exceeded')
            values[key] = value
        # Temporary serialization lets the existing bounded detector recognize
        # paired access credentials and quoted password assignments across fields.
        from peaso.secret_evidence import source_context, named_environment
        if kind == 'lambda':
            named_environment({'Variables': values}, provider='aws', resource_id=arn, scope=account + '/' + region,
                              path='Environment', checks={'aws.htbp.lambda.env_var_names_not_credentials', 'aws_cis_lambda_database_secrets_manager'})
        with source_context(resource_id=arn, scope=account + '/' + region, source=operation,
                            path='Environment.Variables' if kind == 'lambda' else 'Outputs',
                            check_ids={'aws.review.lambda.configuration_secret_indicators' if kind == 'lambda' else 'aws.review.cloudformation.output_secret_indicators'},
                            location_kind='configuration', native=values):
            scanned = inspect_text(json.dumps(values, ensure_ascii=False), 'unused')
        return {'Schema': SCHEMA, 'collection_status': 'collected', 'NativeResponseComplete': True,
            'ResourceArn': arn, 'AccountId': account, 'Region': region, 'SourceOperation': operation,
            'HighConfidenceSecretPresent': scanned['HighConfidenceSecretPresent'],
            'MatchedCategories': scanned['MatchedCategories']}
    except (ValueError, TypeError, UnicodeError):
        return unavailable()


def lambda_indicators(configuration, operation):
    """Only a successful configuration response can prove negative indicators."""
    if not isinstance(configuration, dict):
        return unavailable()
    if operation == 'lambda:ListFunctions':
        # The existing name control also consumes ListFunctions. Preserve the
        # actual returned literals privately before the names-only projection.
        from peaso.secret_evidence import named_environment
        try:
            account, region = _identity(configuration.get('FunctionArn'), configuration.get('FunctionName'), 'lambda')
            named_environment(configuration, provider='aws', resource_id=configuration['FunctionArn'], scope=account + '/' + region,
                              checks={'aws.htbp.lambda.env_var_names_not_credentials', 'aws_cis_lambda_database_secrets_manager'})
        except (ValueError, TypeError, KeyError):
            pass
    if operation != 'lambda:GetFunctionConfiguration':
        return unavailable('not_collected')
    if configuration.get('collection_status', 'collected') != 'collected':
        return unavailable('not_collected')
    environment = configuration.get('Environment', {})
    if (not isinstance(environment, dict) or set(environment) - {'Variables', 'Error'}
            or environment.get('Error') is not None):
        return unavailable('not_collected')
    variables = environment.get('Variables', {})
    if (not isinstance(variables, dict) or len(variables) > MAX_PAIRS or any(not isinstance(key, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,4095}', key)
                                             for key in variables)):
        return unavailable()
    return _indicators(list(variables.items()), configuration.get('FunctionArn'), configuration.get('FunctionName'),
                       'lambda', operation)


def _stack(stack, region):
    from .aws import ReadFailure
    if not isinstance(stack, dict):
        raise ReadFailure('malformed', 'stack_metadata_invalid')
    # Only operational fields already used by the existing native enricher.
    result = {key: deepcopy(stack[key]) for key in STACK_FIELDS if key in stack}
    if isinstance(result.get('DriftInformation'), dict):
        result['DriftInformation'] = {key: deepcopy(result['DriftInformation'][key])
            for key in ('StackDriftStatus', 'LastCheckTimestamp') if key in result['DriftInformation']}
    try:
        account, observed_region = _identity(stack.get('StackId'), stack.get('StackName'), 'stack')
        if region is not None and observed_region != region:
            raise ValueError('stack response belongs to another region')
        if stack.get('StackStatus') not in {'CREATE_COMPLETE', 'ROLLBACK_COMPLETE', 'UPDATE_COMPLETE',
                'UPDATE_ROLLBACK_COMPLETE', 'IMPORT_COMPLETE', 'IMPORT_ROLLBACK_COMPLETE', 'DELETE_COMPLETE'}:
            raise ValueError('stack outputs are not settled')
        outputs = stack.get('Outputs', [])
        if not isinstance(outputs, list) or len(outputs) > MAX_PAIRS:
            raise ValueError('malformed outputs')
        pairs = []
        for output in outputs:
            if not isinstance(output, dict) or set(output) - {'OutputKey', 'OutputValue', 'Description', 'ExportName'}:
                raise ValueError('malformed output row')
            pairs.append((output.get('OutputKey'), output.get('OutputValue')))
        indicator = _indicators(pairs, stack['StackId'], stack['StackName'], 'stack', 'cloudformation:DescribeStacks')
        if stack.get('collection_status', 'collected') != 'collected':
            indicator = unavailable('not_collected')
        result['ConfigurationSecretIndicators'] = indicator
        if stack.get('StackName') == 'CDKToolkit':
            # Existing bootstrap version checks need this non-secret integer.
            # An arbitrary value merely NAMED BootstrapVersion is never retained.
            result['Outputs'] = [{'OutputKey': 'BootstrapVersion', 'OutputValue': value} for key, value in pairs
                if key == 'BootstrapVersion' and isinstance(value, str) and re.fullmatch(r'[0-9]{1,9}', value)]
    except (ValueError, TypeError):
        result['ConfigurationSecretIndicators'] = unavailable()
    return result


def project_cloudformation_response(response, *, region=None):
    """Requests dispatcher MUST call this before placing DescribeStacks in a Future."""
    from .aws import ReadFailure
    if not isinstance(response, dict) or not isinstance(response.get('Stacks'), list):
        raise ReadFailure('malformed', 'stack_listing_metadata_invalid')
    result = {'Stacks': [_stack(stack, region) for stack in response['Stacks']]}
    if 'NextToken' in response:
        token = response['NextToken']
        if not isinstance(token, str) or not token or len(token) > 8192:
            raise ReadFailure('malformed', 'stack_cursor_invalid')
        result['NextToken'] = token  # native pagination cursor, never secret-derived
    return result
