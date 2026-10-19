"""Eight unregistered partial value-indicator checks over safe configuration metadata."""
import re
from .facts import Unavailable, get, list_of_objects
from .aws_configuration_secret_review_20261019 import _member
from peaso.collectors.aws_additional_secret_indicators import SCHEMA
from peaso.collectors.aws_configuration_secret_indicators import CATEGORIES

SURFACES = {
 'codebuild_project': ('name', 'codebuild:BatchGetProjects', {'plaintext_environment'}, 'CodeBuild project'),
 'rest_api_stage': ('id', 'apigateway:GetStages', {'rest_stage_variables'}, 'REST API stage'),
 'ecs_task_definition': ('taskDefinitionArn', 'ecs:DescribeTaskDefinition', {'container_plaintext_environment'}, 'ECS task definition'),
 'amplify_app': ('appId', 'amplify:ListApps', {'app_environment_only'}, 'Amplify app'),
 'batch_job_definition': ('jobDefinitionArn', 'batch:DescribeJobDefinitions', {'classic_container_environment_only'}, 'Batch job definition'),
 'elastic_beanstalk_environment': ('EnvironmentName', 'elasticbeanstalk:DescribeConfigurationSettings', {'configuration_option_values'}, 'Beanstalk environment'),
 'glue_job': ('Name', 'glue:GetJobs', {'default_and_nonoverridable_arguments'}, 'Glue job'),
 'glue_connection': ('Name', 'glue:GetConnections', {'visible_nonpassword_properties', 'returned_connection_properties'}, 'Glue connection'),
}


def _arn(arn, service, account, region):
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if not isinstance(arn, str) or not arn.startswith(f'arn:{partition}:{service}:{region}:{account}:'):
        raise Unavailable('foreign native resource ARN')


def evaluate(kind, item, index):
    try:
        identity_field, operation, coverages, label = SURFACES[kind]
        context = get(index, 'context', dict)
        account, scope = get(context, 'Account', str), get(context, 'scope', str)
        if get(context, 'provider', str) != 'aws' or not re.fullmatch(r'[0-9]{12}', account):
            raise Unavailable('missing AWS account authority')
        if not scope.startswith(account + '/'):
            raise Unavailable('foreign collection scope')
        region = scope.split('/', 1)[1]
        if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+', region):
            raise Unavailable('missing regional authority')
        _member(item, index, kind, identity_field, scope)
        resource_id = get(item, identity_field, str)
        if kind == 'codebuild_project':
            wrapper = get(item, 'Configuration', dict)
            if get(wrapper, 'collection_status', str) != 'collected':
                raise Unavailable('incomplete project response')
            rows = list_of_objects(get(wrapper, 'projects', list))
            if len(rows) != 1 or get(rows[0], 'name', str) != resource_id or get(wrapper, 'projectsNotFound', list):
                raise Unavailable('project identity unresolved')
            raw = rows[0]
            _arn(get(raw, 'arn', str), 'codebuild', account, region)
            if not raw['arn'].endswith(':project/' + resource_id):
                raise Unavailable('mismatched project ARN')
        elif kind == 'ecs_task_definition':
            wrapper = get(item, 'Definition', dict)
            if get(wrapper, 'collection_status', str) != 'collected':
                raise Unavailable('incomplete task definition')
            raw = get(wrapper, 'taskDefinition', dict)
            if get(raw, 'taskDefinitionArn', str) != resource_id:
                raise Unavailable('task identity mismatch')
            _arn(resource_id, 'ecs', account, region)
        elif kind == 'elastic_beanstalk_environment':
            raw = get(item, 'Configuration', dict)
            if get(raw, 'collection_status', str) != 'collected':
                raise Unavailable('incomplete environment settings')
            resource_id = get(item, 'ApplicationName', str) + '/' + resource_id
            if 'EnvironmentArn' in item:
                _arn(get(item, 'EnvironmentArn', str), 'elasticbeanstalk', account, region)
                if not item['EnvironmentArn'].endswith(':environment/' + resource_id):
                    raise Unavailable('environment identity mismatch')
        else:
            raw = item
            if kind == 'amplify_app':
                _arn(get(item, 'appArn', str), 'amplify', account, region)
                if not item['appArn'].endswith(':apps/' + resource_id):
                    raise Unavailable('app identity mismatch')
            elif kind == 'batch_job_definition':
                _arn(resource_id, 'batch', account, region)
            elif kind == 'rest_api_stage':
                parent, stage = get(item, 'ParentApiId', str), get(item, 'stageName', str)
                partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
                if resource_id != f'arn:{partition}:apigateway:{region}::/restapis/{parent}/stages/{stage}':
                    raise Unavailable('stage parent mismatch')
                resource_id = parent + '/' + stage
        marker = get(raw, 'AdditionalSecretIndicators', dict)
        expected = {'Schema', 'collection_status', 'NativeResponseComplete', 'Kind', 'ResourceId', 'AccountId',
                    'Region', 'SourceOperation', 'Coverage', 'HighConfidenceSecretPresent', 'MatchedCategories'}
        if (set(marker) != expected or get(marker, 'Schema', str) != SCHEMA or get(marker, 'collection_status', str) != 'collected'
                or get(marker, 'NativeResponseComplete', bool) is not True or get(marker, 'Kind', str) != kind
                or get(marker, 'ResourceId', str) != resource_id or marker['AccountId'] not in (None, account)
                or get(marker, 'Region', str) != region or get(marker, 'SourceOperation', str) != operation
                or get(marker, 'Coverage', str) not in coverages):
            raise Unavailable('indicator provenance incomplete')
        if kind in {'codebuild_project', 'ecs_task_definition', 'amplify_app', 'batch_job_definition'} and marker['AccountId'] != account:
            raise Unavailable('ARN account evidence absent')
        categories = get(marker, 'MatchedCategories', list)
        present = get(marker, 'HighConfidenceSecretPresent', bool)
        if (any(not isinstance(c, str) or c not in CATEGORIES for c in categories) or len(set(categories)) != len(categories)
                or present != bool(categories)):
            raise Unavailable('incoherent indicators')
        short = resource_id.rsplit('/', 1)[-1][:28]
        observed = label + ' ' + short + (': a selected secret indicator was observed.' if present else ': no selected secret indicator was observed.')
        return ('FAIL' if present else 'PASS'), {'observed': observed, 'resource_id': resource_id,
            'matched_categories': list(categories), 'coverage': marker['Coverage'], 'partial_detector': True}
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError):
        return 'UNKNOWN', {'observed': 'Complete matching configuration indicator evidence is unavailable.'}


def codebuild(item, index=None): return evaluate('codebuild_project', item, index or {})
def rest_stage(item, index=None): return evaluate('rest_api_stage', item, index or {})
def ecs(item, index=None): return evaluate('ecs_task_definition', item, index or {})
def amplify(item, index=None): return evaluate('amplify_app', item, index or {})
def batch(item, index=None): return evaluate('batch_job_definition', item, index or {})
def beanstalk(item, index=None): return evaluate('elastic_beanstalk_environment', item, index or {})
def glue_job(item, index=None): return evaluate('glue_job', item, index or {})
def glue_connection(item, index=None): return evaluate('glue_connection', item, index or {})


SOURCE_LINEAGE = {'codebuild_project_no_secrets_in_variables': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/codebuild/codebuild_project_no_secrets_in_variables/codebuild_project_no_secrets_in_variables.py',
                                               'sha256': '60c3f43e59d0457be6c2f809bd19c295b8cd09bf73f358ea792f6986ea1805f1'},
 'apigateway_restapi_no_secrets_in_stage_variables': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/apigateway/apigateway_restapi_no_secrets_in_stage_variables/apigateway_restapi_no_secrets_in_stage_variables.py',
                                                      'sha256': 'f18f3c5bcf6a9f4c39d18dadd1f75f8a0808e7ab4a7d07b41434486969e3ae4b'},
 'ecs_task_definitions_no_environment_secrets': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/ecs/ecs_task_definitions_no_environment_secrets/ecs_task_definitions_no_environment_secrets.py',
                                                 'sha256': 'e7774707f46aefb1abe6594198a79d3f9c9e30d9a42cc638dc9c92023d6bae12'},
 'amplify_app_no_secrets_in_environment': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/amplify/amplify_app_no_secrets_in_environment/amplify_app_no_secrets_in_environment.py',
                                           'sha256': '5d48340a16581173c9b2a7f9b522a4f104c6e387c9635a46a5efe341c4f2f9a6'},
 'batch_job_definition_no_secrets': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/batch/batch_job_definition_no_secrets/batch_job_definition_no_secrets.py',
                                     'sha256': '97a42ebb97801e65a14aa3c541a323207ecf461d922229fea650e1523fdeb2b9'},
 'elasticbeanstalk_environment_no_secrets_in_configuration': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/elasticbeanstalk/elasticbeanstalk_environment_no_secrets_in_configuration/elasticbeanstalk_environment_no_secrets_in_configuration.py',
                                                              'sha256': 'd94ea11c0b97ef27fdd3c85f27564974be2e802a6def1f472d6b1a6bf3cb3d5c'},
 'glue_etl_jobs_no_secrets_in_arguments': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/glue/glue_etl_jobs_no_secrets_in_arguments/glue_etl_jobs_no_secrets_in_arguments.py',
                                           'sha256': '8f4f42ec254d562374da15c65d9db93fcf8622655857303cba3ce2eafa48b567'},
 'glue_catalog_connection_no_secrets': {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/glue/glue_catalog_connection_no_secrets/glue_catalog_connection_no_secrets.py',
                                        'sha256': '6f1f3e09fe0e993cab3997c54c5a151b7ab861862e8da12e803abcafb799a17c'}}

DETAILS = [
 ('codebuild_project', 'codebuild', 'codebuild_project_no_secrets_in_variables',
  'CodeBuild plaintext environment variables', 'Configuration.projects[].AdditionalSecretIndicators',
  'Only explicitly typed PLAINTEXT variables are scanned before CodeBuild redaction; Parameter Store and Secrets Manager references are not resolved. Existing name/type-only checks are independent.',
  'Move literal build credentials into managed secret references and rotate confirmed exposures.'),
 ('rest_api_stage', 'rest_stage', 'apigateway_restapi_no_secrets_in_stage_variables',
  'REST API stage variable values', 'AdditionalSecretIndicators bound to ParentApiId and stageName',
  'The exact REST API stage variables are scanned before caching, with parent API and stage identity verified; HTTP API stages are outside this check.',
  'Replace plaintext stage credentials with service integration or managed secret references.'),
 ('ecs_task_definition', 'ecs', 'ecs_task_definitions_no_environment_secrets',
  'ECS container plaintext environment entries', 'Definition.taskDefinition.AdditionalSecretIndicators',
  'Every native container environment list is inspected independently, with task-definition ARN and revision binding; external secrets and environment files are not read.',
  'Use ECS secret references instead of literal container credentials and rotate confirmed leaked values.'),
 ('amplify_app', 'amplify', 'amplify_app_no_secrets_in_environment',
  'Amplify app environment variable contents', 'AdditionalSecretIndicators bound to appId and appArn',
  'Only app environment maps returned by ListApps are inspected; backend metadata supplies no variable contents. Build specifications, custom headers and backend-stack contents are omitted and unclaimed.',
  'Remove literal credentials from Amplify app variables and use supported secret references.'),
 ('batch_job_definition', 'batch', 'batch_job_definition_no_secrets',
  'Batch classic container environment entries', 'AdditionalSecretIndicators bound to jobDefinitionArn',
  'Classic containerProperties environment entries are scanned; command content is discarded without inspection. Multi-node, ECS and EKS Batch variants remain UNKNOWN rather than receiving a negative scan.',
  'Replace Batch container credential literals with secret references and rotate verified exposures.'),
 ('elastic_beanstalk_environment', 'beanstalk', 'elasticbeanstalk_environment_no_secrets_in_configuration',
  'Beanstalk configuration option values', 'Configuration.AdditionalSecretIndicators',
  'All option values in the uniquely matching requested ApplicationName/EnvironmentName setting are inspected; only previously supported nonsecret option enums remain in configuration metadata.',
  'Remove hardcoded credentials from Beanstalk configuration options and use a managed secret integration.'),
 ('glue_job', 'glue_job', 'glue_etl_jobs_no_secrets_in_arguments',
  'Glue job default and nonoverridable arguments', 'AdditionalSecretIndicators bound to Name and regional collection authority',
  'DefaultArguments and NonOverridableArguments are inspected separately before caching; script files, job runs and external argument values are not read. Only known nonsecret flag enums remain.',
  'Remove literal Glue job argument credentials and use connections or managed secret references.'),
 ('glue_connection', 'glue_connection', 'glue_catalog_connection_no_secrets',
  'Glue visible connection property values', 'AdditionalSecretIndicators bound to Name, catalog and regional collection authority',
  'The existing HidePassword=True read covers visible nonpassword ConnectionProperties only. Hidden PASSWORD/ENCRYPTED_PASSWORD, authentication and engine-specific maps are neither inspected nor certified clean.',
  'Replace exposed visible connection property credentials with managed secret references; review hidden passwords separately.'),
]
DECLARATIONS, ADMISSION_DATA = [], {'schema_version': 1, 'checks': []}
for _kind, _function, _source, _label, _field, _limitation, _remediation in DETAILS:
    _id = 'aws.review.' + _kind + '.configuration_secret_indicators'
    _description = {'description': 'Observes selected high-confidence secret indicators in ' + _label + '. ' + _limitation +
        ' A negative result means no selected indicator in complete bound returned evidence, not absence of all secrets.',
        'evaluated': [_field, 'complete matching ' + _kind + ' native collection and AWS context account/region'],
        'pass_when': 'Complete bound ' + _label + ' evidence contains no selected high-confidence indicator.',
        'fail_when': 'Complete bound ' + _label + ' evidence contains a private-key marker, paired AWS credentials or literal password assignment.',
        'not_applicable_when': 'No automatic exclusion; denied, malformed, incomplete, foreign, unknown-type or unsupported evidence is UNKNOWN.'}
    DECLARATIONS.append({'id': _id, 'provider': 'aws', 'kind': _kind, 'evaluator': _function, 'category': 'hardening',
        'severity': 'high', 'control': 'configuration_secrets', 'target': 'resource', 'dependencies': [_kind],
        'title': _label + ' have no observed selected secret indicators', 'remediation': _remediation})
    ADMISSION_DATA['checks'].append({'spec': {'id': _id, 'provider': 'aws', 'resource_kind': _kind,
        'data_source': ', '.join(_description['evaluated']), 'predicate': _description['fail_when'] + ' ' + _description['pass_when'],
        'severity': 'high', 'category': 'hardening', 'title': DECLARATIONS[-1]['title'],
        'description': _description['description'], 'remediation_hint': _remediation}, 'description': _description,
        'sources': [SOURCE_LINEAGE[_source]], 'requirements': [],
        'function': 'peaso.checks.aws_additional_secret_review_20261019:' + _function,
        'review_notes': 'Corrected partial replacement for ' + _source + ': bounded high-confidence categories replace the full external content scanner; '
            'no credential validation, scanner ignore patterns or exhaustive secret discovery is claimed. ' + _limitation +
            ' Raw values are discarded before shared Futures/cache and never copied into evidence or value hashes; scope/identity/completeness are mandatory.'})


def _runtime_fixture(kind, detected):
    account, region, scope = '123456789012', 'us-east-1', '123456789012/us-east-1'
    identity_field, operation, coverages, _ = SURFACES[kind]
    arn = lambda service, resource: f'arn:aws:{service}:{region}:{account}:{resource}'
    base = {
      'codebuild_project': {'name': 'example'},
      'rest_api_stage': {'id': f'arn:aws:apigateway:{region}::/restapis/abc123/stages/prod', 'ParentApiId': 'abc123', 'stageName': 'prod'},
      'ecs_task_definition': {'taskDefinitionArn': arn('ecs', 'task-definition/example:1')},
      'amplify_app': {'appId': 'dexample', 'appArn': arn('amplify', 'apps/dexample')},
      'batch_job_definition': {'jobDefinitionArn': arn('batch', 'job-definition/example:1')},
      'elastic_beanstalk_environment': {'ApplicationName': 'app', 'EnvironmentName': 'prod', 'EnvironmentArn': arn('elasticbeanstalk', 'environment/app/prod')},
      'glue_job': {'Name': 'example'}, 'glue_connection': {'Name': 'example'},
    }[kind]
    resource_id = base[identity_field]
    if kind == 'rest_api_stage': resource_id = 'abc123/prod'
    if kind == 'elastic_beanstalk_environment': resource_id = 'app/prod'
    marker = {'Schema': SCHEMA, 'collection_status': 'collected', 'NativeResponseComplete': True, 'Kind': kind,
        'ResourceId': resource_id, 'AccountId': account if kind in {'codebuild_project', 'ecs_task_definition', 'amplify_app', 'batch_job_definition'} else None,
        'Region': region, 'SourceOperation': operation, 'Coverage': sorted(coverages)[0],
        'HighConfidenceSecretPresent': detected, 'MatchedCategories': ['password_assignment'] if detected else []}
    if kind == 'codebuild_project':
        base['Configuration'] = {'collection_status': 'collected', 'projectsNotFound': [], 'projects': [
            {'name': 'example', 'arn': arn('codebuild', 'project/example'), 'AdditionalSecretIndicators': marker}]}
    elif kind == 'ecs_task_definition':
        base['Definition'] = {'collection_status': 'collected', 'taskDefinition': {'taskDefinitionArn': resource_id, 'AdditionalSecretIndicators': marker}}
    elif kind == 'elastic_beanstalk_environment':
        base['Configuration'] = {'collection_status': 'collected', 'AdditionalSecretIndicators': marker}
    else:
        base['AdditionalSecretIndicators'] = marker
    index = {'context': {'provider': 'aws', 'Account': account, 'scope': scope},
        'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [base]}]},
        kind: [{'type': kind, 'scope': scope, 'data': base}]}
    return base, index


RUNTIME_CASES = {}
for _declaration in DECLARATIONS:
    _good, _good_index = _runtime_fixture(_declaration['kind'], False)
    _bad, _bad_index = _runtime_fixture(_declaration['kind'], True)
    RUNTIME_CASES[_declaration['id']] = {'pass': _good, 'index': _good_index, 'pass_index': _good_index,
        'fail': _bad, 'fail_index': _bad_index, 'missing': {}, 'malformed': None}
