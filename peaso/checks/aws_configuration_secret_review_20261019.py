"""Unregistered, read-only safe configuration-secret indicator predicates.

Only the explicitly documented partial high-confidence detector is evaluated.
No absence of all secrets, credential validity or effective access is inferred.
"""
from .facts import Unavailable, get, list_of_objects, memoized
from peaso.collectors.aws_configuration_secret_indicators import SCHEMA, CATEGORIES, _identity

REVISION = '803dda1f7555ed5cea959aef30cfa0719b030d8c'


def _member(item, index, kind, identity, scope):
    def collect():
        envelopes = get(get(index, 'collections', dict), kind, list)
        if not envelopes:
            raise Unavailable('configuration inventory was not collected')
        members = {}
        for envelope in envelopes:
            if (get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != scope
                    or get(envelope, 'status', str) != 'collected'):
                raise Unavailable('configuration inventory incomplete or foreign')
            for row in list_of_objects(get(envelope, 'items', list)):
                arn = get(row, identity, str)
                if arn in members:
                    raise Unavailable('duplicate native configuration identity')
                members[arn] = row
        return members
    members = memoized(index, ('configuration-secret-members-v1', kind, scope), collect)
    arn = get(item, identity, str)
    if arn not in members or members[arn] != item:
        raise Unavailable('resource does not match complete native configuration inventory')


def _evaluate(item, index, kind):
    try:
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'aws':
            raise Unavailable('AWS provider authority missing')
        scope, account = get(context, 'scope', str), get(context, 'Account', str)
        is_lambda = kind == 'lambda_function'
        identity, name = ('FunctionArn', 'FunctionName') if is_lambda else ('StackId', 'StackName')
        arn = get(item, identity, str)
        observed_account, region = _identity(arn, get(item, name, str), 'lambda' if is_lambda else 'stack')
        if observed_account != account or scope != account + '/' + region:
            raise Unavailable('configuration resource scope mismatch')
        _member(item, index, kind, identity, scope)
        if is_lambda:
            configuration = get(item, 'Configuration', dict)
            if (get(configuration, 'collection_status', str) != 'collected'
                    or get(configuration, 'FunctionArn', str) != arn
                    or get(configuration, 'FunctionName', str) != get(item, name, str)):
                raise Unavailable('Lambda configuration response incomplete or identity mismatched')
            indicator = get(configuration, 'ConfigurationSecretIndicators', dict)
            operation = 'lambda:GetFunctionConfiguration'
        else:
            indicator = get(item, 'ConfigurationSecretIndicators', dict)
            operation = 'cloudformation:DescribeStacks'
        expected_fields = {'Schema', 'collection_status', 'NativeResponseComplete', 'ResourceArn', 'AccountId',
                           'Region', 'SourceOperation', 'HighConfidenceSecretPresent', 'MatchedCategories'}
        if (set(indicator) != expected_fields or get(indicator, 'Schema', str) != SCHEMA
                or get(indicator, 'collection_status', str) != 'collected'
                or get(indicator, 'NativeResponseComplete', bool) is not True
                or get(indicator, 'ResourceArn', str) != arn or get(indicator, 'AccountId', str) != account
                or get(indicator, 'Region', str) != region or get(indicator, 'SourceOperation', str) != operation):
            raise Unavailable('safe configuration indicator provenance incomplete or mismatched')
        present = get(indicator, 'HighConfidenceSecretPresent', bool)
        categories = get(indicator, 'MatchedCategories', list)
        if (any(not isinstance(category, str) or category not in CATEGORIES for category in categories)
                or len(set(categories)) != len(categories) or present != bool(categories)):
            raise Unavailable('safe indicator categories are malformed or contradictory')
        target = 'Lambda function' if is_lambda else 'CloudFormation stack'
        native_name = get(item, name, str)
        shortname = native_name[:32] + ('…' if len(native_name) > 32 else '')
        sentence = (target + ' ' + shortname + ': a high-confidence secret indicator was observed.' if present else
                    target + ' ' + shortname + ': no selected secret indicators were observed in the complete response.')
        return ('FAIL' if present else 'PASS'), {'observed': sentence, 'resource_arn': arn, 'matched_categories': list(categories),
            'high_confidence_secret_present': present, 'scope': 'bounded partial configuration heuristic; not exhaustive secret discovery'}
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError):
        # Error values are intentionally not interpolated: malformed provider
        # fields must never copy content into finding evidence or diagnostics.
        return 'UNKNOWN', {'observed': 'Complete, matching safe configuration indicator evidence is unavailable.'}


def lambda_environment(item, index=None):
    return _evaluate(item, {} if index is None else index, 'lambda_function')


def cloudformation_outputs(item, index=None):
    return _evaluate(item, {} if index is None else index, 'cloudformation_stack')


# Explicit supervisor intake. These are useful partial configuration controls;
# broad historical compliance links are not inherited without separate review.
DECLARATIONS = [
    {'id': 'aws.review.lambda.configuration_secret_indicators', 'kind': 'lambda_function',
     'evaluator': 'lambda_environment', 'severity': 'high', 'category': 'hardening',
     'title': 'Lambda environment has no observed high-confidence secret indicators',
     'remediation': 'Move literal credentials into a managed secret reference and rotate any credential confirmed exposed; retain only references in Lambda configuration.',
     'source_file': 'lambda.pp', 'source_sha256': '473b668bc143f4f096ee893f4c3f78ca1badf1113153959c69a440d2e1e857ab',
     'upstream_id': 'lambda_function_variables_no_sensitive_data',
     'fields': ['FunctionArn', 'FunctionName', 'Configuration.FunctionArn', 'Configuration.FunctionName',
                'Configuration.collection_status', 'Configuration.ConfigurationSecretIndicators', 'complete same-scope lambda_function collection'],
     'official_docs': ['https://docs.aws.amazon.com/lambda/latest/api/API_GetFunctionConfiguration.html']},
    {'id': 'aws.review.cloudformation.output_secret_indicators', 'kind': 'cloudformation_stack',
     'evaluator': 'cloudformation_outputs', 'severity': 'high', 'category': 'hardening',
     'title': 'CloudFormation outputs have no observed high-confidence secret indicators',
     'remediation': 'Remove literal credentials from stack outputs, publish references instead, and rotate any credential confirmed exposed.',
     'source_file': 'cloudformation.pp', 'source_sha256': '503fec114cfbe0c1204a8d205b587b452a3ee7a62f0bf2ec6f72953322c349bf',
     'upstream_id': 'cloudformation_stack_output_no_secrets',
     'fields': ['StackId', 'StackName', 'ConfigurationSecretIndicators', 'complete same-scope cloudformation_stack collection'],
     'official_docs': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStacks.html',
                       'https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_Output.html']},
]

for _declaration in DECLARATIONS:
    _declaration.update(provider='aws', dependencies=[_declaration['kind']], target='resource', control='configuration_secrets')

ADMISSION_DATA = {'schema_version': 1, 'checks': []}
for _declaration in DECLARATIONS:
    _description = {
        'description': 'Observes private-key markers, paired AWS access credentials and literal password assignments using a bounded partial configuration detector. '
                       'Values are inspected only before shared caching, then discarded; complete matching provenance is required. '
                       'A negative indicator does not prove that configuration contains no secrets.',
        'evaluated': _declaration['fields'],
        'pass_when': 'A complete, matching native response has no selected high-confidence indicator.',
        'fail_when': 'A complete, matching native response contains at least one selected high-confidence indicator.',
        'not_applicable_when': 'No automatic applicability exception; unavailable, malformed, partial, foreign or empty-status evidence is UNKNOWN.'}
    ADMISSION_DATA['checks'].append({
        'spec': {'id': _declaration['id'], 'provider': 'aws', 'resource_kind': _declaration['kind'],
                 'data_source': ', '.join(_declaration['fields']),
                 'predicate': _description['fail_when'] + ' ' + _description['pass_when'] + ' ' + _description['not_applicable_when'],
                 'severity': _declaration['severity'], 'category': _declaration['category'], 'title': _declaration['title'],
                 'description': _description['description'], 'remediation_hint': _declaration['remediation']},
        'description': _description,
        'sources': [{'url': 'https://github.com/turbot/steampipe-mod-aws-compliance/blob/' + REVISION + '/conformance_pack/' + _declaration['source_file'],
                     'sha256': _declaration['source_sha256']}],
        'requirements': [],
        'review_notes': 'Corrected partial replacement for ' + _declaration['upstream_id'] + ': pinned SQL matches pass/secret/token/key substrings in both names and values '
                        'and an unanchored character-mix expression, causing benign keyword false positives. '
                        'The CloudFormation SQL starts from jsonb_array_elements(outputs), so null/empty output stacks emit no row despite its later null-output branch. '
                        'Native negative results mean only that selected high-confidence indicators were absent from a successfully inspected response, not absence of all secrets. '
                        'Malformed/unreadable evidence is not converted into empty/clean; safe markers retain no literals, value hashes, snippets, output keys or reconstructible secret tokens. '
                        'Unsettled stack operations are UNKNOWN rather than certifying outputs not yet available. CloudFormation preserves only validated numeric CDKToolkit BootstrapVersion for existing operational checks; no other output values are retained.',
        'official_docs': _declaration['official_docs'],
        'function': 'peaso.checks.aws_configuration_secret_review_20261019:' + _declaration['evaluator']})


def _runtime_fixture(kind, detected):
    account, region = '123456789012', 'us-east-1'
    arn = ('arn:aws:lambda:us-east-1:123456789012:function:worker' if kind == 'lambda_function' else
           'arn:aws:cloudformation:us-east-1:123456789012:stack/demo/11111111-2222-3333-4444-555555555555')
    indicator = {'Schema': SCHEMA, 'collection_status': 'collected', 'NativeResponseComplete': True,
        'ResourceArn': arn, 'AccountId': account, 'Region': region,
        'SourceOperation': 'lambda:GetFunctionConfiguration' if kind == 'lambda_function' else 'cloudformation:DescribeStacks',
        'HighConfidenceSecretPresent': detected, 'MatchedCategories': ['password_assignment'] if detected else []}
    if kind == 'lambda_function':
        item = {'FunctionArn': arn, 'FunctionName': 'worker', 'Configuration': {'FunctionArn': arn, 'FunctionName': 'worker',
            'collection_status': 'collected', 'ConfigurationSecretIndicators': indicator}}
    else:
        item = {'StackId': arn, 'StackName': 'demo', 'ConfigurationSecretIndicators': indicator}
    scope = account + '/' + region
    index = {'context': {'provider': 'aws', 'Account': account, 'scope': scope},
        'collections': {kind: [{'type': kind, 'scope': scope, 'status': 'collected', 'items': [item]}]},
        kind: [{'type': kind, 'scope': scope, 'data': item}]}
    return item, index


RUNTIME_CASES = {}
for _declaration in DECLARATIONS:
    _good, _good_index = _runtime_fixture(_declaration['kind'], False)
    _bad, _bad_index = _runtime_fixture(_declaration['kind'], True)
    RUNTIME_CASES[_declaration['id']] = {'pass': _good, 'pass_index': _good_index, 'index': _good_index,
        'fail': _bad, 'fail_index': _bad_index, 'missing': {}, 'malformed': None}
