"""Selected ECS task-definition literals stay bound to the exact native revision."""

import pytest

from peaso.collectors import aws_selected_configuration_secret_indicators as source


ARN = 'arn:aws:ecs:us-east-1:123456789012:task-definition/AuditTask:3'
INFO = {'surface': 'ecs_environment', 'account': '123456789012',
        'region': 'us-east-1', 'partition': 'aws'}
ARGS = {'taskDefinition': ARN}


def definition(*, log_options=None, firelens_options=None):
    container = {'name': 'app', 'environment': [{'name': 'MODE', 'value': 'production'}],
                 'logConfiguration': {'logDriver': 'awslogs', 'options': log_options or {},
                                      'secretOptions': [{'name': 'token', 'valueFrom': 'secret-manager-reference'}]},
                 'firelensConfiguration': {'type': 'fluentbit', 'options': firelens_options or {}}}
    return {'taskDefinition': {'taskDefinitionArn': ARN, 'family': 'AuditTask',
            'revision': 3, 'status': 'ACTIVE', 'containerDefinitions': [container]}}


def test_inline_logging_options_are_inspected_but_secret_references_are_not():
    response = definition(log_options={'api-key': 'literal-log-value'},
                          firelens_options={'license': 'literal-firelens-value'})
    payload, count = source.extract(response, 'ecs', 'describe_task_definition', ARGS, INFO)
    assert count == 3
    assert b'logConfiguration.options.api-key=literal-log-value' in payload
    assert b'firelensConfiguration.options.license=literal-firelens-value' in payload
    assert b'secret-manager-reference' not in payload


@pytest.mark.parametrize('options', [None, [], {'api-key': 42}, {'': 'value'}])
def test_malformed_inline_options_cannot_prove_a_clean_result(options):
    response = definition()
    response['taskDefinition']['containerDefinitions'][0]['logConfiguration']['options'] = options
    with pytest.raises(ValueError):
        source.extract(response, 'ecs', 'describe_task_definition', ARGS, INFO)


def test_foreign_task_revision_is_rejected_before_inspection():
    response = definition(log_options={'api-key': 'literal-log-value'})
    response['taskDefinition']['revision'] = 4
    with pytest.raises(ValueError):
        source.extract(response, 'ecs', 'describe_task_definition', ARGS, INFO)
