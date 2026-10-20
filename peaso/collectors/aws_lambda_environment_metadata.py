"""Keep Lambda variable names for controls, omitting values before caching."""
from copy import deepcopy
import re


def _unavailable():
    return {'Error': {'ErrorCode': 'environment_metadata_unavailable'}}


def _environment(value, operation):
    if (not isinstance(value, dict) or set(value) - {'Variables', 'Error'}
            or value.get('Error') is not None):
        return _unavailable()
    result = {}
    if 'Variables' in value:
        variables = value['Variables']
        if (not isinstance(variables, dict) or
                any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,4095}', name)
                    for name in variables)):
            return _unavailable()
        # Existing count/name readers inspect the keys, never these placeholders.
        # Null explicitly means omitted; it is not a retrieved variable value.
        result['Variables'] = dict.fromkeys(variables)
    result['_provenance'] = {'source_operation': operation, 'read_only': True, 'values_omitted': True}
    return result


def _configuration(value, operation):
    if not isinstance(value, dict):
        from .aws import ReadFailure
        raise ReadFailure('malformed', 'lambda_configuration_metadata_invalid')
    from .aws_configuration_secret_indicators import lambda_indicators
    indicator = lambda_indicators(value, operation)
    result = {key: _environment(child, operation) if key == 'Environment' else deepcopy(child)
              for key, child in value.items() if key != 'ConfigurationSecretIndicators'}
    result['ConfigurationSecretIndicators'] = indicator
    return result


def project_response(response, operation):
    """Preserve paging and unrelated configuration without copying env values."""
    if operation == 'get_function_configuration':
        return _configuration(response, 'lambda:GetFunctionConfiguration')
    if operation != 'list_functions' or not isinstance(response, dict) or not isinstance(response.get('Functions'), list):
        from .aws import ReadFailure
        raise ReadFailure('malformed', 'lambda_listing_metadata_invalid')
    return {key: [_configuration(row, 'lambda:ListFunctions') for row in child]
            if key == 'Functions' else deepcopy(child) for key, child in response.items()}
