"""Reviewed pre-cache Security Hub finding metadata projection.

GetFindings remains a read-only, account and Region filtered request at callers.
The SDK required ASFF shape is checked before only reviewed control fields are copied.
"""
from functools import lru_cache
from .aws import ReadFailure

PROFILE = 'securityhub-findings-metadata-v1'
PROJECTION_OPERATIONS = frozenset({('securityhub', 'get_findings')})
_REQUIRED_STRINGS = ('SchemaVersion', 'Id', 'ProductArn', 'GeneratorId',
                     'AwsAccountId', 'CreatedAt', 'UpdatedAt', 'Title', 'Description')
_METADATA_STRINGS = ('Id', 'AwsAccountId', 'Region', 'ProductArn',
                     'CreatedAt', 'UpdatedAt', 'RecordState')


def _invalid():
    raise ReadFailure('malformed', 'securityhub_finding_metadata_invalid') from None


@lru_cache(maxsize=1)
def _output_shape():
    import botocore.session
    return botocore.session.get_session().get_service_model('securityhub').operation_model('GetFindings').output_shape


def project_response(response, service, operation, arguments):
    if (service, operation) not in PROJECTION_OPERATIONS or not isinstance(response, dict):
        _invalid()
    from botocore.validate import validate_parameters
    from botocore.exceptions import ParamValidationError
    try:
        validate_parameters({key: value for key, value in response.items()
                             if key != 'ResponseMetadata'}, _output_shape())
    except ParamValidationError:
        _invalid()
    findings = response.get('Findings')
    if not isinstance(findings, list):
        _invalid()
    projected = []
    for finding in findings:
        if (not isinstance(finding, dict)
                or any(not isinstance(finding.get(key), str) for key in _REQUIRED_STRINGS)
                or not isinstance(finding.get('Resources'), list)):
            _invalid()
        row = {key: finding[key] for key in _METADATA_STRINGS if key in finding}
        for key in ('Severity', 'Workflow'):
            value = finding.get(key)
            if value is not None:
                field = 'Label' if key == 'Severity' else 'Status'
                if not isinstance(value, dict) or (field in value and not isinstance(value[field], str)):
                    _invalid()
                row[key] = {field: value[field]} if field in value else {}
        if any(key in finding and not isinstance(finding[key], str) for key in _METADATA_STRINGS):
            _invalid()
        projected.append(row)
    safe = {'Findings': projected}
    if 'NextToken' in response:
        if not isinstance(response['NextToken'], str) or not response['NextToken']:
            _invalid()
        safe['NextToken'] = response['NextToken']
    return safe
