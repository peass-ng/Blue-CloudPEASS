"""Read-only Bedrock role/key-owner configuration predicates.

Static policy algebra reuses the pinned Prowler engines already in this repo.
These are configured-policy checks, never effective-access or invocation tests.
Registration is explicit so the coordinator can admit all metadata atomically.
"""
from __future__ import annotations

from functools import wraps
import re

from . import result, unknown
from .facts import Unavailable, get, guard, list_of_objects
from .aws_a_facts import api_optional, complete_items
from .claude_aws_a_iam_prowler import admin_access, effective_actions, expand, privilege_escalation, statements_of

IDS = ('aws.bedrock.agent_role_least_privilege',
       'aws.bedrock.agent_role_not_shared_across_agents',
       'aws.bedrock.api_key_no_administrative_privileges')
PROFILE = 'bedrock-agent-role-account-v1'
ACCOUNT = re.compile(r'[0-9]{12}')
ROLE = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):iam::([0-9]{12}):role/.+')
AGENT = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):bedrock:([a-z0-9-]+):([0-9]{12}):agent/([A-Za-z0-9]{10})')
# Generated below from the digest-pinned iamdata wheel, never a runtime network read.
# iamdata==0.1.202605131, wheel SHA256:
# 350e317d96fb8c8ddf30aa6da222788d302af5f13c9e357b59f9eefe50b8af5a
BEDROCK_ACTIONS = frozenset((
    'bedrock:AllowVendedLogDeliveryForResource',
    'bedrock:ApplyGuardrail',
    'bedrock:AssociateAgentCollaborator',
    'bedrock:AssociateAgentKnowledgeBase',
    'bedrock:AssociateThirdPartyKnowledgeBase',
    'bedrock:BatchDeleteEvaluationJob',
    'bedrock:CallWithBearerToken',
    'bedrock:CancelAutomatedReasoningPolicyBuildWorkflow',
    'bedrock:CopyBlueprintStage',
    'bedrock:CountTokens',
    'bedrock:CreateAgent',
    'bedrock:CreateAgentActionGroup',
    'bedrock:CreateAgentAlias',
    'bedrock:CreateAutomatedReasoningPolicy',
    'bedrock:CreateAutomatedReasoningPolicyTestCase',
    'bedrock:CreateAutomatedReasoningPolicyVersion',
    'bedrock:CreateBlueprint',
    'bedrock:CreateBlueprintVersion',
    'bedrock:CreateCustomModel',
    'bedrock:CreateCustomModelDeployment',
    'bedrock:CreateDataAutomationLibrary',
    'bedrock:CreateDataAutomationProject',
    'bedrock:CreateDataSource',
    'bedrock:CreateEvaluationJob',
    'bedrock:CreateFlow',
    'bedrock:CreateFlowAlias',
    'bedrock:CreateFlowVersion',
    'bedrock:CreateFoundationModelAgreement',
    'bedrock:CreateGuardrail',
    'bedrock:CreateGuardrailVersion',
    'bedrock:CreateInferenceProfile',
    'bedrock:CreateInvocation',
    'bedrock:CreateKnowledgeBase',
    'bedrock:CreateMarketplaceModelEndpoint',
    'bedrock:CreateModelCopyJob',
    'bedrock:CreateModelCustomizationJob',
    'bedrock:CreateModelEvaluationJob',
    'bedrock:CreateModelImportJob',
    'bedrock:CreateModelInvocationJob',
    'bedrock:CreatePrompt',
    'bedrock:CreatePromptRouter',
    'bedrock:CreatePromptVersion',
    'bedrock:CreateProvisionedModelThroughput',
    'bedrock:CreateSession',
    'bedrock:DeleteAgent',
    'bedrock:DeleteAgentActionGroup',
    'bedrock:DeleteAgentAlias',
    'bedrock:DeleteAgentMemory',
    'bedrock:DeleteAgentVersion',
    'bedrock:DeleteAutomatedReasoningPolicy',
    'bedrock:DeleteAutomatedReasoningPolicyBuildWorkflow',
    'bedrock:DeleteAutomatedReasoningPolicyTestCase',
    'bedrock:DeleteBlueprint',
    'bedrock:DeleteCustomModel',
    'bedrock:DeleteCustomModelDeployment',
    'bedrock:DeleteDataAutomationLibrary',
    'bedrock:DeleteDataAutomationProject',
    'bedrock:DeleteDataSource',
    'bedrock:DeleteEnforcedGuardrailConfiguration',
    'bedrock:DeleteFlow',
    'bedrock:DeleteFlowAlias',
    'bedrock:DeleteFlowVersion',
    'bedrock:DeleteFoundationModelAgreement',
    'bedrock:DeleteGuardrail',
    'bedrock:DeleteImportedModel',
    'bedrock:DeleteInferenceProfile',
    'bedrock:DeleteKnowledgeBase',
    'bedrock:DeleteKnowledgeBaseDocuments',
    'bedrock:DeleteMarketplaceModelAgreement',
    'bedrock:DeleteMarketplaceModelEndpoint',
    'bedrock:DeleteModelInvocationLoggingConfiguration',
    'bedrock:DeletePrompt',
    'bedrock:DeletePromptRouter',
    'bedrock:DeleteProvisionedModelThroughput',
    'bedrock:DeleteResourcePolicy',
    'bedrock:DeleteSession',
    'bedrock:DeregisterMarketplaceModelEndpoint',
    'bedrock:DetectGeneratedContent',
    'bedrock:DisassociateAgentCollaborator',
    'bedrock:DisassociateAgentKnowledgeBase',
    'bedrock:EndSession',
    'bedrock:ExportAutomatedReasoningPolicyVersion',
    'bedrock:GenerateQuery',
    'bedrock:GetAgent',
    'bedrock:GetAgentActionGroup',
    'bedrock:GetAgentAlias',
    'bedrock:GetAgentCollaborator',
    'bedrock:GetAgentKnowledgeBase',
    'bedrock:GetAgentMemory',
    'bedrock:GetAgentVersion',
    'bedrock:GetAsyncInvoke',
    'bedrock:GetAutomatedReasoningPolicy',
    'bedrock:GetAutomatedReasoningPolicyAnnotations',
    'bedrock:GetAutomatedReasoningPolicyBuildWorkflow',
    'bedrock:GetAutomatedReasoningPolicyBuildWorkflowResultAssets',
    'bedrock:GetAutomatedReasoningPolicyNextScenario',
    'bedrock:GetAutomatedReasoningPolicyTestCase',
    'bedrock:GetAutomatedReasoningPolicyTestResult',
    'bedrock:GetBlueprint',
    'bedrock:GetBlueprintOptimizationStatus',
    'bedrock:GetBlueprintRecommendation',
    'bedrock:GetCustomModel',
    'bedrock:GetCustomModelDeployment',
    'bedrock:GetDataAutomationLibrary',
    'bedrock:GetDataAutomationLibraryEntity',
    'bedrock:GetDataAutomationLibraryIngestionJob',
    'bedrock:GetDataAutomationProject',
    'bedrock:GetDataAutomationStatus',
    'bedrock:GetDataSource',
    'bedrock:GetEvaluationJob',
    'bedrock:GetExecutionFlowSnapshot',
    'bedrock:GetFlow',
    'bedrock:GetFlowAlias',
    'bedrock:GetFlowExecution',
    'bedrock:GetFlowVersion',
    'bedrock:GetFoundationModel',
    'bedrock:GetFoundationModelAvailability',
    'bedrock:GetGuardrail',
    'bedrock:GetImportedModel',
    'bedrock:GetInferenceProfile',
    'bedrock:GetIngestionJob',
    'bedrock:GetInvocationStep',
    'bedrock:GetKnowledgeBase',
    'bedrock:GetKnowledgeBaseDocuments',
    'bedrock:GetMarketplaceModelEndpoint',
    'bedrock:GetModelCopyJob',
    'bedrock:GetModelCustomizationJob',
    'bedrock:GetModelEvaluationJob',
    'bedrock:GetModelImportJob',
    'bedrock:GetModelInvocationJob',
    'bedrock:GetModelInvocationLoggingConfiguration',
    'bedrock:GetPrompt',
    'bedrock:GetPromptRouter',
    'bedrock:GetProvisionedModelThroughput',
    'bedrock:GetResourcePolicy',
    'bedrock:GetSession',
    'bedrock:GetUseCaseForModelAccess',
    'bedrock:IngestKnowledgeBaseDocuments',
    'bedrock:InvokeAgent',
    'bedrock:InvokeAutomatedReasoningPolicy',
    'bedrock:InvokeBlueprintOptimizationAsync',
    'bedrock:InvokeBlueprintRecommendationAsync',
    'bedrock:InvokeBuilder',
    'bedrock:InvokeDataAutomation',
    'bedrock:InvokeDataAutomationAsync',
    'bedrock:InvokeDataAutomationLibraryIngestionJob',
    'bedrock:InvokeFlow',
    'bedrock:InvokeInlineAgent',
    'bedrock:InvokeModel',
    'bedrock:InvokeModelWithResponseStream',
    'bedrock:InvokeTool',
    'bedrock:ListAgentActionGroups',
    'bedrock:ListAgentAliases',
    'bedrock:ListAgentCollaborators',
    'bedrock:ListAgentKnowledgeBases',
    'bedrock:ListAgentVersions',
    'bedrock:ListAgents',
    'bedrock:ListAsyncInvokes',
    'bedrock:ListAutomatedReasoningPolicies',
    'bedrock:ListAutomatedReasoningPolicyBuildWorkflows',
    'bedrock:ListAutomatedReasoningPolicyTestCases',
    'bedrock:ListAutomatedReasoningPolicyTestResults',
    'bedrock:ListBlueprints',
    'bedrock:ListCustomModelDeployments',
    'bedrock:ListCustomModels',
    'bedrock:ListDataAutomationLibraries',
    'bedrock:ListDataAutomationLibraryEntities',
    'bedrock:ListDataAutomationLibraryIngestionJobs',
    'bedrock:ListDataAutomationProjects',
    'bedrock:ListDataSources',
    'bedrock:ListEnforcedGuardrailsConfiguration',
    'bedrock:ListEvaluationJobs',
    'bedrock:ListFlowAliases',
    'bedrock:ListFlowExecutionEvents',
    'bedrock:ListFlowExecutions',
    'bedrock:ListFlowVersions',
    'bedrock:ListFlows',
    'bedrock:ListFoundationModelAgreementOffers',
    'bedrock:ListFoundationModels',
    'bedrock:ListGuardrails',
    'bedrock:ListImportedModels',
    'bedrock:ListInferenceProfiles',
    'bedrock:ListIngestionJobs',
    'bedrock:ListInvocationSteps',
    'bedrock:ListInvocations',
    'bedrock:ListKnowledgeBaseDocuments',
    'bedrock:ListKnowledgeBases',
    'bedrock:ListMarketplaceModelEndpoints',
    'bedrock:ListModelCopyJobs',
    'bedrock:ListModelCustomizationJobs',
    'bedrock:ListModelEvaluationJobs',
    'bedrock:ListModelImportJobs',
    'bedrock:ListModelInvocationJobs',
    'bedrock:ListPromptRouters',
    'bedrock:ListPrompts',
    'bedrock:ListProvisionedModelThroughputs',
    'bedrock:ListSessions',
    'bedrock:ListTagsForResource',
    'bedrock:OptimizePrompt',
    'bedrock:PrepareAgent',
    'bedrock:PrepareFlow',
    'bedrock:PutEnforcedGuardrailConfiguration',
    'bedrock:PutFoundationModelEntitlement',
    'bedrock:PutInvocationStep',
    'bedrock:PutModelInvocationLoggingConfiguration',
    'bedrock:PutResourcePolicy',
    'bedrock:PutUseCaseForModelAccess',
    'bedrock:RegisterMarketplaceModelEndpoint',
    'bedrock:RenderPrompt',
    'bedrock:Rerank',
    'bedrock:Retrieve',
    'bedrock:RetrieveAndGenerate',
    'bedrock:StartAutomatedReasoningPolicyBuildWorkflow',
    'bedrock:StartAutomatedReasoningPolicyTestWorkflow',
    'bedrock:StartFlowExecution',
    'bedrock:StartIngestionJob',
    'bedrock:StopEvaluationJob',
    'bedrock:StopFlowExecution',
    'bedrock:StopIngestionJob',
    'bedrock:StopModelCustomizationJob',
    'bedrock:StopModelInvocationJob',
    'bedrock:TagResource',
    'bedrock:UntagResource',
    'bedrock:UpdateAgent',
    'bedrock:UpdateAgentActionGroup',
    'bedrock:UpdateAgentAlias',
    'bedrock:UpdateAgentCollaborator',
    'bedrock:UpdateAgentKnowledgeBase',
    'bedrock:UpdateAutomatedReasoningPolicy',
    'bedrock:UpdateAutomatedReasoningPolicyAnnotations',
    'bedrock:UpdateAutomatedReasoningPolicyTestCase',
    'bedrock:UpdateBlueprint',
    'bedrock:UpdateCustomModelDeployment',
    'bedrock:UpdateDataAutomationLibrary',
    'bedrock:UpdateDataAutomationProject',
    'bedrock:UpdateDataSource',
    'bedrock:UpdateFlow',
    'bedrock:UpdateFlowAlias',
    'bedrock:UpdateGuardrail',
    'bedrock:UpdateKnowledgeBase',
    'bedrock:UpdateMarketplaceModelEndpoint',
    'bedrock:UpdatePrompt',
    'bedrock:UpdateProvisionedModelThroughput',
    'bedrock:UpdateSession',
    'bedrock:ValidateFlowDefinition',
))
SEMANTICS = 'Pinned Prowler configured-policy algebra; resource conditions, boundaries and SCP enforcement are not effective-access claims'


def _safe(function):
    @wraps(function)
    def evaluate(item, index):
        try:
            guard(item)
            return function(item, index)
        except (Unavailable, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
            return unknown('Bedrock role/key-owner evidence unavailable or malformed', error_type=type(exc).__name__,
                           observed='Required Bedrock execution-role or policy evidence is unavailable or malformed.')
    return evaluate


def _short(value):
    name = value.rsplit('/', 1)[-1]
    return name if len(name) <= 24 else name[:21] + '...'


def _scope(index):
    scope = get(index, 'context.scope', str)
    parts = scope.split('/')
    if (len(parts) != 2 or ACCOUNT.fullmatch(parts[0]) is None or
            parts[1] != 'global' and re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]', parts[1]) is None):
        raise Unavailable('verified AWS account/region context unavailable')
    return scope, parts[0], parts[1]


def _role_arn(value, account):
    match = ROLE.fullmatch(value) if isinstance(value, str) else None
    if match is None or match[2] != account:
        raise Unavailable('role ARN does not belong to the scoped account')
    return value


def _agent_role(item, account, region=None):
    identifier = get(item, 'agentId', str)
    detail = get(item, 'AgentRoleMetadata', dict)
    if get(detail, 'collection_status', str) != 'collected' or get(detail, 'agentId', str) != identifier:
        raise Unavailable('agent draft role metadata unavailable or mismatched')
    arn = get(detail, 'agentArn', str)
    match = AGENT.fullmatch(arn)
    if match is None or match[3] != account or match[4] != identifier or region is not None and match[2] != region:
        raise Unavailable('agent ARN/account/region mismatch')
    if get(detail, 'agentVersion', str) != 'DRAFT':
        raise Unavailable('GetAgent draft representation required')
    return arn, _role_arn(get(detail, 'agentResourceRoleArn', str), account)


def _policy_document(document):
    get(document, 'Statement')
    statements = get(document, 'Statement')
    if isinstance(statements, dict):
        statements = [statements]
    for statement in list_of_objects(statements):
        if get(statement, 'Effect', str) not in {'Allow', 'Deny'}:
            raise Unavailable('unknown IAM statement effect')
        for positive, negative in [('Action', 'NotAction'), ('Resource', 'NotResource')]:
            if (positive in statement) == (negative in statement):
                raise Unavailable('IAM statement requires exactly one action/resource selector')
            value = get(statement, positive if positive in statement else negative)
            if not (isinstance(value, str) and value or isinstance(value, list) and value and
                    all(isinstance(entry, str) and entry for entry in value)):
                raise Unavailable('malformed IAM selector')
        if 'Condition' in statement:
            get(statement, 'Condition', dict)
    return document


def _documents(principal, index, account, inline_field):
    """Resolve every attached document; explicit coverage governs omissions."""
    operation = 'iam:GetAccountAuthorizationDetails'
    inline = list_of_objects(api_optional(principal, inline_field, list, [], operation=operation))
    attached = list_of_objects(api_optional(principal, 'AttachedManagedPolicies', list, [], operation=operation))
    documents = [_policy_document(get(row, 'PolicyDocument', dict)) for row in inline]
    policy_arns = [get(row, 'PolicyArn', str) for row in attached]
    if len(policy_arns) != len(set(policy_arns)):
        raise Unavailable('duplicate managed policy attachments')
    if not policy_arns:
        return documents
    policies = complete_items(index, 'iam_policy', account + '/global')
    for arn in policy_arns:
        if not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::(?:aws|' + account + r'):policy/.+', arn):
            raise Unavailable('foreign or malformed managed policy ARN')
        matches = [row for row in policies if get(row, 'Arn', str) == arn]
        if len(matches) != 1:
            raise Unavailable('attached policy missing or ambiguous')
        versions = list_of_objects(get(matches[0], 'PolicyVersionList', list))
        defaults = [row for row in versions if get(row, 'IsDefaultVersion', bool)]
        if len(defaults) != 1:
            raise Unavailable('managed default policy document unresolved')
        documents.append(_policy_document(get(defaults[0], 'Document', dict)))
    return documents


def _full_bedrock(document):
    if not BEDROCK_ACTIONS:
        raise Unavailable('pinned Bedrock action catalog unavailable')
    if not BEDROCK_ACTIONS <= effective_actions(document, BEDROCK_ACTIONS):
        return False
    on_all = set()
    for statement in statements_of(document):
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        if statement['Effect'] != 'Allow' or '*' not in resources:
            continue
        on_all.update(expand(statement.get('Action'), BEDROCK_ACTIONS))
        if statement.get('NotAction'):
            on_all.update(BEDROCK_ACTIONS - expand(statement['NotAction'], BEDROCK_ACTIONS))
    return BEDROCK_ACTIONS <= on_all


def _partial_envelope(parent, key):
    """Read an explicitly partial inventory prefix; never promote it to complete."""
    guard(parent)
    coverage = parent.get('_coverage', {}).get(key)
    if coverage is not None and (not isinstance(coverage, dict) or coverage.get('status') not in {'collected', 'empty'}):
        raise Unavailable('inventory field coverage unavailable')
    value = parent.get(key)
    if not isinstance(value, dict) or not isinstance(value.get('collection_status'), str):
        raise Unavailable('inventory envelope missing or malformed')
    status = value['collection_status']
    if status not in {'collected', 'empty', 'partial', 'denied', 'unknown', 'not_collected', 'malformed'}:
        raise Unavailable('unrecognized inventory coverage')
    rows = list_of_objects(value.get('items'))
    field_coverage = value.get('_coverage', {})
    if not isinstance(field_coverage, dict):
        raise Unavailable('malformed partial inventory field coverage')
    for field in ('items', 'collection_status'):
        marker = field_coverage.get(field)
        if marker is not None and (not isinstance(marker, dict) or marker.get('status') not in {'collected', 'empty'}):
            raise Unavailable('partial inventory field unavailable')
        if field == 'items' and marker is not None and marker['status'] == 'empty' and rows:
            raise Unavailable('empty field coverage contradicts retained inventory rows')
    if status in {'empty', 'denied', 'unknown', 'not_collected', 'malformed'} and rows:
        raise Unavailable('inventory coverage contradicts retained rows')
    return rows, status in {'collected', 'empty'}


@_safe
def agent_role_least_privilege(item, index):
    scope, account, region = _scope(index)
    agent, role_arn = _agent_role(item, account, region)
    roles = complete_items(index, 'iam_role', scope)
    matches = [role for role in roles if get(role, 'Arn', str) == role_arn]
    if len(matches) != 1:
        raise Unavailable('agent role missing or ambiguous in IAM')
    role = matches[0]
    attached = list_of_objects(api_optional(role, 'AttachedManagedPolicies', list, [], operation='iam:GetAccountAuthorizationDetails'))
    for policy in attached:
        arn = get(policy, 'PolicyArn', str)
        if re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::aws:policy/.*FullAccess', arn):
            return result(True, agent_arn=agent, role_arn=role_arn, violation='AWS-managed FullAccess policy', policy_arn=arn, semantics=SEMANTICS,
                          observed=f"Agent {item['agentId']} role {_short(role_arn)} has an AWS-managed FullAccess policy.")
    boundary = api_optional(role, 'PermissionsBoundary', dict, {}, operation='iam:GetAccountAuthorizationDetails')
    if not boundary:
        return result(True, agent_arn=agent, role_arn=role_arn, violation='permissions boundary absent', semantics=SEMANTICS,
                      observed=f"Agent {item['agentId']} role {_short(role_arn)} has no permissions boundary.")
    if get(boundary, 'PermissionsBoundaryType', str) != 'PermissionsBoundaryPolicy':
        raise Unavailable('malformed permissions boundary metadata')
    boundary_arn = get(boundary, 'PermissionsBoundaryArn', str)
    if not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::(?:aws|' + account + r'):policy/.+', boundary_arn):
        raise Unavailable('malformed or foreign permissions boundary ARN')
    for document in _documents(role, index, account, 'RolePolicyList'):
        if admin_access(document) or privilege_escalation(document):
            return result(True, agent_arn=agent, role_arn=role_arn, violation='administrative or known escalation permissions', semantics=SEMANTICS,
                          observed=f"Agent {item['agentId']} role {_short(role_arn)} has a prohibited administrative or escalation policy match.")
    return result(False, agent_arn=agent, role_arn=role_arn, permissions_boundary_configured=True, semantics=SEMANTICS,
                  observed=f"Agent {item['agentId']} role {_short(role_arn)} has a boundary and no prohibited match in complete policy evidence.")


@_safe
def api_key_no_administrative_privileges(item, index):
    scope, account, _region = _scope(index)
    if get(item, 'ServiceName', str) != 'bedrock.amazonaws.com':
        return 'NOT_APPLICABLE', {'reason': 'credential belongs to another service'}
    credential = get(item, 'ServiceSpecificCredentialId', str)
    username = get(item, 'UserName', str)
    if not credential or re.fullmatch(r'[A-Za-z0-9+=,.@_-]{1,64}', username) is None:
        raise Unavailable('credential or username identity malformed')
    users = complete_items(index, 'iam_user', scope)
    matches = [user for user in users if get(user, 'UserName', str) == username]
    if len(matches) != 1:
        raise Unavailable('Bedrock API key owner unresolved or ambiguous')
    user = matches[0]
    arn = get(user, 'Arn', str)
    if not re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::' + account + r':user/.+', arn):
        raise Unavailable('credential owner belongs to another account')
    for document in _documents(user, index, account, 'UserPolicyList'):
        if admin_access(document) or privilege_escalation(document) or _full_bedrock(document):
            return result(True, credential_id=credential, username=username, violation='administrative, known escalation or full Bedrock service permissions', semantics=SEMANTICS,
                          observed=f'Bedrock key {_short(credential)} owner {_short(username)} has a prohibited administrative, escalation or full-service policy match.')
    return result(False, credential_id=credential, username=username, semantics=SEMANTICS,
                  observed=f'Bedrock key {_short(credential)} owner {_short(username)} has no prohibited match in complete policy evidence.')


@_safe
def agent_role_not_shared_across_agents(item, index):
    _scope_value, account, region = _scope(index)
    target, target_draft = _agent_role(item, account, region)
    envelopes = get(index, 'collections.bedrock_agent_account_inventory', list)
    if len(envelopes) != 1:
        raise Unavailable('account-wide role inventory missing or ambiguous')
    envelope = envelopes[0]
    if (get(envelope, 'scope', str) != account + '/global' or
            get(envelope, 'account_id', str) != account or get(envelope, 'global', bool) is not True):
        raise Unavailable('account-wide inventory scope is not verified')
    complete = get(envelope, 'status', str) in {'collected', 'empty'}
    rows = list_of_objects(get(envelope, 'items', list))
    if len(rows) != 1:
        raise Unavailable('account-wide proof missing or ambiguous')
    proof = rows[0]
    if get(proof, 'AccountId', str) != account or get(proof, 'profile', str) != PROFILE:
        raise Unavailable('account-wide role proof identity mismatch')
    coverage_rows, coverage_complete = _partial_envelope(proof, 'EnabledRegions')
    complete = complete and coverage_complete
    enabled = [get(row, 'RegionName', str) for row in coverage_rows]
    if len(enabled) != len(set(enabled)) or not enabled or region not in enabled:
        raise Unavailable('enabled Region coverage missing or ambiguous')
    region_rows = list_of_objects(get(proof, 'RegionAgents', list))
    represented = [get(row, 'Region', str) for row in region_rows]
    if len(represented) != len(set(represented)):
        raise Unavailable('duplicate Region observations')
    complete = complete and set(represented) == set(enabled)
    role_agents = {}
    seen_agents = set()
    target_roles = {target_draft}
    target_seen = False
    for regional in region_rows:
        observed_region = get(regional, 'Region', str)
        if observed_region not in enabled:
            raise Unavailable('unexpected Region in account inventory')
        agent_rows, agents_complete = _partial_envelope(regional, 'Agents')
        complete = complete and agents_complete
        for agent in agent_rows:
            try:
                arn, role = _agent_role(agent, account, observed_region)
                if arn in seen_agents:
                    raise Unavailable('duplicate agent identity')
                seen_agents.add(arn)
                held = {role}
            except Unavailable:
                complete = False
                continue
            try:
                version_rows, versions_complete = _partial_envelope(agent, 'DeployedRoleVersions')
                complete = complete and versions_complete
                for version in version_rows:
                    if not re.fullmatch(r'[1-9][0-9]{0,4}', get(version, 'agentVersion', str)):
                        raise Unavailable('malformed deployed version')
                    held.add(_role_arn(get(version, 'agentResourceRoleArn', str), account))
            except Unavailable:
                complete = False
            if arn == target:
                target_seen = True
                if role != target_draft:
                    raise Unavailable('contradictory target draft role observations')
                target_roles.update(held)
            for role in held:
                role_agents.setdefault(role, set()).add(arn)
    shared = sorted(role for role in target_roles if len(role_agents.get(role, set()) - {target}) > 0)
    if shared:
        return result(True, agent_arn=target, shared_role_arns=shared, inventory_complete=complete,
                      observed=f"Agent {item['agentId']} shares role {_short(shared[0])} with another observed agent.",
                      semantics='Account-wide observed draft and alias-routed version roles; configured role reuse only')
    if not complete or not target_seen:
        raise Unavailable('incomplete account/Region/agent/deployed-version coverage prevents dedication PASS')
    return result(False, agent_arn=target, role_arns=sorted(target_roles), inventory_complete=True,
                  observed=f"Agent {item['agentId']} has dedicated draft and alias-routed roles across all enabled Regions.",
                  semantics='Account-wide draft and alias-routed version role uniqueness')




# Coordinator intake: this module deliberately does not register itself.
ADMISSION_DATA = {'schema_version': 1,
 'checks': [{'spec': {'id': 'aws.bedrock.agent_role_least_privilege',
                      'provider': 'aws',
                      'resource_kind': 'bedrock_agent',
                      'data_source': 'AgentRoleMetadata, IAM role boundaries and complete inline/attached '
                                     'policy documents',
                      'predicate': 'A known AWS-managed FullAccess attachment, administrative/escalation '
                                   'permission match, or absent permissions boundary is observed. UNKNOWN: '
                                   'required facts are unavailable, malformed, foreign or ambiguous.',
                      'severity': 'high',
                      'category': 'least_privilege',
                      'title': 'Bedrock agent execution role follows least privilege',
                      'description': 'Bedrock agent execution role follows least privilege. Checks collected '
                                     'configuration only; unreadable, missing, ambiguous or incomplete '
                                     'evidence remains UNKNOWN. It does not establish effective access or '
                                     'runtime enforcement.',
                      'remediation_hint': 'Review the named role or user policies, permissions boundary and '
                                          'agent/version role assignments; grant only required permissions.'},
             'description': {'description': 'Bedrock agent execution role follows least privilege. Checks '
                                            'collected configuration only; unreadable, missing, ambiguous or '
                                            'incomplete evidence remains UNKNOWN. It does not establish '
                                            'effective access or runtime enforcement.',
                             'evaluated': ['AgentRoleMetadata, IAM role boundaries and complete '
                                           'inline/attached policy documents'],
                             'pass_when': 'The agent execution role is resolved, a boundary exists, every '
                                          'attached/inline policy is resolved, and no prohibited policy '
                                          'pattern matches.',
                             'fail_when': 'A known AWS-managed FullAccess attachment, '
                                          'administrative/escalation permission match, or absent permissions '
                                          'boundary is observed.',
                             'not_applicable_when': 'Only collected Bedrock agent resources are evaluated.'},
             'sources': [{'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/bedrock/bedrock_agent_role_least_privilege/bedrock_agent_role_least_privilege.py',
                          'sha256': '74951419e5bce998e2f27735b0a77c3a1a9eea1c8047e5cd8701cfad2a400e53'}],
             'requirements': [],
             'dependencies': ['bedrock_agent', 'iam_role', 'iam_policy'],
             'review_notes': 'Pinned Prowler static policy algebra; 101 permission-combination patterns '
                             'match pinned current source. Every referenced policy must resolve before PASS, '
                             'improving upstream skip-on-missing behavior. The 245-action Bedrock slice is '
                             'from iamdata==0.1.202605131, matching the existing helper catalog. No model '
                             'invocation or dynamic permission testing.',
             'function': 'peaso.checks.aws_bedrock_review_20261019:agent_role_least_privilege'},
            {'spec': {'id': 'aws.bedrock.agent_role_not_shared_across_agents',
                      'provider': 'aws',
                      'resource_kind': 'bedrock_agent',
                      'data_source': 'AgentRoleMetadata and complete enabled-Region agent draft/alias-routed '
                                     'role inventory',
                      'predicate': 'An execution role held by the agent draft or an alias-routed version is '
                                   'also held by another observed agent. UNKNOWN: required facts are '
                                   'unavailable, malformed, foreign or ambiguous.',
                      'severity': 'high',
                      'category': 'least_privilege',
                      'title': 'Bedrock agent execution roles are dedicated across the account',
                      'description': 'Bedrock agent execution roles are dedicated across the account. Checks '
                                     'collected configuration only; unreadable, missing, ambiguous or '
                                     'incomplete evidence remains UNKNOWN. A witnessed duplicate can FAIL '
                                     'despite unrelated inventory gaps.',
                      'remediation_hint': 'Review the named role or user policies, permissions boundary and '
                                          'agent/version role assignments; grant only required permissions.'},
             'description': {'description': 'Bedrock agent execution roles are dedicated across the account. '
                                            'Checks collected configuration only; unreadable, missing, '
                                            'ambiguous or incomplete evidence remains UNKNOWN. A witnessed '
                                            'duplicate can FAIL despite unrelated inventory gaps.',
                             'evaluated': ['AgentRoleMetadata and complete enabled-Region agent '
                                           'draft/alias-routed role inventory'],
                             'pass_when': 'Complete enabled-Region, agent draft and alias-routed-version '
                                          'coverage shows that none of the agent roles is held by another '
                                          'agent.',
                             'fail_when': 'An execution role held by the agent draft or an alias-routed '
                                          'version is also held by another observed agent.',
                             'not_applicable_when': 'Only collected Bedrock agent resources are evaluated.'},
             'sources': [{'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/bedrock/bedrock_agent_role_not_shared_across_agents/bedrock_agent_role_not_shared_across_agents.py',
                          'sha256': 'be412a4fb101afe322e854a977e6419e2950fcc9f757e7b8f15c6cd565b1c487'}],
             'requirements': [],
             'dependencies': ['bedrock_agent', 'bedrock_agent_account_inventory'],
             'review_notes': 'Pinned Prowler static policy algebra; 101 permission-combination patterns '
                             'match pinned current source. Every referenced policy must resolve before PASS, '
                             'improving upstream skip-on-missing behavior. The 245-action Bedrock slice is '
                             'from iamdata==0.1.202605131, matching the existing helper catalog. No model '
                             'invocation or dynamic permission testing.',
             'function': 'peaso.checks.aws_bedrock_review_20261019:agent_role_not_shared_across_agents'},
            {'spec': {'id': 'aws.bedrock.api_key_no_administrative_privileges',
                      'provider': 'aws',
                      'resource_kind': 'iam_service_specific_credential',
                      'data_source': 'Bedrock service-specific credential UserName and complete IAM user '
                                     'inline/attached policy documents',
                      'predicate': 'A resolved owner policy matches pinned administrative, escalation or '
                                   'full Bedrock service permission algebra. UNKNOWN: required facts are '
                                   'unavailable, malformed, foreign or ambiguous.',
                      'severity': 'high',
                      'category': 'least_privilege',
                      'title': 'Bedrock API key owner has no administrative permissions',
                      'description': 'Bedrock API key owner has no administrative permissions. Checks '
                                     'collected configuration only; unreadable, missing, ambiguous or '
                                     'incomplete evidence remains UNKNOWN. It does not establish effective '
                                     'access or runtime enforcement.',
                      'remediation_hint': 'Review the named role or user policies, permissions boundary and '
                                          'agent/version role assignments; grant only required permissions.'},
             'description': {'description': 'Bedrock API key owner has no administrative permissions. Checks '
                                            'collected configuration only; unreadable, missing, ambiguous or '
                                            'incomplete evidence remains UNKNOWN. It does not establish '
                                            'effective access or runtime enforcement.',
                             'evaluated': ['Bedrock service-specific credential UserName and complete IAM '
                                           'user inline/attached policy documents'],
                             'pass_when': 'The credential owner and every attached/inline policy are '
                                          'resolved and none matches the prohibited policy algebra.',
                             'fail_when': 'A resolved owner policy matches pinned administrative, escalation '
                                          'or full Bedrock service permission algebra.',
                             'not_applicable_when': 'The service-specific credential belongs to another '
                                                    'service.'},
             'sources': [{'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/bedrock/bedrock_api_key_no_administrative_privileges/bedrock_api_key_no_administrative_privileges.py',
                          'sha256': '4be81d76a1f11d70eece2e02251f827491fd73830f43520175256195cf95fcaf'}],
             'requirements': [],
             'dependencies': ['iam_service_specific_credential', 'iam_user', 'iam_policy'],
             'review_notes': 'Pinned Prowler static policy algebra; 101 permission-combination patterns '
                             'match pinned current source. Every referenced policy must resolve before PASS, '
                             'improving upstream skip-on-missing behavior. The 245-action Bedrock slice is '
                             'from iamdata==0.1.202605131, matching the existing helper catalog. No model '
                             'invocation or dynamic permission testing.',
             'function': 'peaso.checks.aws_bedrock_review_20261019:api_key_no_administrative_privileges'}]}

RUNTIME_CASES = {'aws.bedrock.agent_role_least_privilege': {'pass': {'agentId': 'ABCDEFGHIJ',
                                                     'AgentRoleMetadata': {'agentId': 'ABCDEFGHIJ',
                                                                           'agentArn': 'arn:aws:bedrock:us-east-1:123456789012:agent/ABCDEFGHIJ',
                                                                           'agentVersion': 'DRAFT',
                                                                           'agentResourceRoleArn': 'arn:aws:iam::123456789012:role/agent',
                                                                           'collection_status': 'collected'},
                                                     'DeployedRoleVersions': {'collection_status': 'empty',
                                                                              'items': []}},
                                            'fail': {'agentId': 'ABCDEFGHIJ',
                                                     'AgentRoleMetadata': {'agentId': 'ABCDEFGHIJ',
                                                                           'agentArn': 'arn:aws:bedrock:us-east-1:123456789012:agent/ABCDEFGHIJ',
                                                                           'agentVersion': 'DRAFT',
                                                                           'agentResourceRoleArn': 'arn:aws:iam::123456789012:role/agent',
                                                                           'collection_status': 'collected'},
                                                     'DeployedRoleVersions': {'collection_status': 'empty',
                                                                              'items': []}},
                                            'pass_index': {'context': {'scope': '123456789012/us-east-1'},
                                                           'collections': {'iam_role': [{'type': 'iam_role',
                                                                                         'scope': '123456789012/global',
                                                                                         'account_id': '123456789012',
                                                                                         'global': True,
                                                                                         'status': 'collected',
                                                                                         'items': [{'Arn': 'arn:aws:iam::123456789012:role/agent',
                                                                                                    'AttachedManagedPolicies': [],
                                                                                                    'RolePolicyList': [],
                                                                                                    '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails',
                                                                                                                    'native_response_complete': True},
                                                                                                    'PermissionsBoundary': {'PermissionsBoundaryType': 'PermissionsBoundaryPolicy',
                                                                                                                            'PermissionsBoundaryArn': 'arn:aws:iam::123456789012:policy/boundary'}}]}]}},
                                            'fail_index': {'context': {'scope': '123456789012/us-east-1'},
                                                           'collections': {'iam_role': [{'type': 'iam_role',
                                                                                         'scope': '123456789012/global',
                                                                                         'account_id': '123456789012',
                                                                                         'global': True,
                                                                                         'status': 'collected',
                                                                                         'items': [{'Arn': 'arn:aws:iam::123456789012:role/agent',
                                                                                                    'AttachedManagedPolicies': [],
                                                                                                    'RolePolicyList': [],
                                                                                                    '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails',
                                                                                                                    'native_response_complete': True}}]}]}},
                                            'missing': {},
                                            'malformed': None},
 'aws.bedrock.agent_role_not_shared_across_agents': {'pass': {'agentId': 'ABCDEFGHIJ',
                                                              'AgentRoleMetadata': {'agentId': 'ABCDEFGHIJ',
                                                                                    'agentArn': 'arn:aws:bedrock:us-east-1:123456789012:agent/ABCDEFGHIJ',
                                                                                    'agentVersion': 'DRAFT',
                                                                                    'agentResourceRoleArn': 'arn:aws:iam::123456789012:role/agent',
                                                                                    'collection_status': 'collected'},
                                                              'DeployedRoleVersions': {'collection_status': 'empty',
                                                                                       'items': []}},
                                                     'fail': {'agentId': 'ABCDEFGHIJ',
                                                              'AgentRoleMetadata': {'agentId': 'ABCDEFGHIJ',
                                                                                    'agentArn': 'arn:aws:bedrock:us-east-1:123456789012:agent/ABCDEFGHIJ',
                                                                                    'agentVersion': 'DRAFT',
                                                                                    'agentResourceRoleArn': 'arn:aws:iam::123456789012:role/agent',
                                                                                    'collection_status': 'collected'},
                                                              'DeployedRoleVersions': {'collection_status': 'empty',
                                                                                       'items': []}},
                                                     'pass_index': {'context': {'scope': '123456789012/us-east-1'},
                                                                    'collections': {'bedrock_agent_account_inventory': [{'type': 'bedrock_agent_account_inventory',
                                                                                                                         'scope': '123456789012/global',
                                                                                                                         'account_id': '123456789012',
                                                                                                                         'global': True,
                                                                                                                         'status': 'collected',
                                                                                                                         'items': [{'AccountId': '123456789012',
                                                                                                                                    'profile': 'bedrock-agent-role-account-v1',
                                                                                                                                    'EnabledRegions': {'collection_status': 'collected',
                                                                                                                                                       'items': [{'RegionName': 'us-east-1'}]},
                                                                                                                                    'RegionAgents': [{'Region': 'us-east-1',
                                                                                                                                                      'Agents': {'collection_status': 'collected',
                                                                                                                                                                 'items': [{'agentId': 'ABCDEFGHIJ',
                                                                                                                                                                            'AgentRoleMetadata': {'agentId': 'ABCDEFGHIJ',
                                                                                                                                                                                                  'agentArn': 'arn:aws:bedrock:us-east-1:123456789012:agent/ABCDEFGHIJ',
                                                                                                                                                                                                  'agentVersion': 'DRAFT',
                                                                                                                                                                                                  'agentResourceRoleArn': 'arn:aws:iam::123456789012:role/agent',
                                                                                                                                                                                                  'collection_status': 'collected'},
                                                                                                                                                                            'DeployedRoleVersions': {'collection_status': 'empty',
                                                                                                                                                                                                     'items': []}}]}}]}]}]}},
                                                     'fail_index': {'context': {'scope': '123456789012/us-east-1'},
                                                                    'collections': {'bedrock_agent_account_inventory': [{'type': 'bedrock_agent_account_inventory',
                                                                                                                         'scope': '123456789012/global',
                                                                                                                         'account_id': '123456789012',
                                                                                                                         'global': True,
                                                                                                                         'status': 'collected',
                                                                                                                         'items': [{'AccountId': '123456789012',
                                                                                                                                    'profile': 'bedrock-agent-role-account-v1',
                                                                                                                                    'EnabledRegions': {'collection_status': 'collected',
                                                                                                                                                       'items': [{'RegionName': 'us-east-1'}]},
                                                                                                                                    'RegionAgents': [{'Region': 'us-east-1',
                                                                                                                                                      'Agents': {'collection_status': 'collected',
                                                                                                                                                                 'items': [{'agentId': 'ABCDEFGHIJ',
                                                                                                                                                                            'AgentRoleMetadata': {'agentId': 'ABCDEFGHIJ',
                                                                                                                                                                                                  'agentArn': 'arn:aws:bedrock:us-east-1:123456789012:agent/ABCDEFGHIJ',
                                                                                                                                                                                                  'agentVersion': 'DRAFT',
                                                                                                                                                                                                  'agentResourceRoleArn': 'arn:aws:iam::123456789012:role/agent',
                                                                                                                                                                                                  'collection_status': 'collected'},
                                                                                                                                                                            'DeployedRoleVersions': {'collection_status': 'empty',
                                                                                                                                                                                                     'items': []}},
                                                                                                                                                                           {'agentId': 'KLMNOPQRST',
                                                                                                                                                                            'AgentRoleMetadata': {'agentId': 'KLMNOPQRST',
                                                                                                                                                                                                  'agentArn': 'arn:aws:bedrock:us-east-1:123456789012:agent/KLMNOPQRST',
                                                                                                                                                                                                  'agentVersion': 'DRAFT',
                                                                                                                                                                                                  'agentResourceRoleArn': 'arn:aws:iam::123456789012:role/agent',
                                                                                                                                                                                                  'collection_status': 'collected'},
                                                                                                                                                                            'DeployedRoleVersions': {'collection_status': 'empty',
                                                                                                                                                                                                     'items': []}}]}}]}]}]}},
                                                     'missing': {},
                                                     'malformed': None},
 'aws.bedrock.api_key_no_administrative_privileges': {'pass': {'ServiceName': 'bedrock.amazonaws.com',
                                                               'ServiceSpecificCredentialId': 'ACCAEXAMPLE',
                                                               'UserName': 'alice'},
                                                      'fail': {'ServiceName': 'bedrock.amazonaws.com',
                                                               'ServiceSpecificCredentialId': 'ACCAEXAMPLE',
                                                               'UserName': 'alice'},
                                                      'pass_index': {'context': {'scope': '123456789012/us-east-1'},
                                                                     'collections': {'iam_user': [{'type': 'iam_user',
                                                                                                   'scope': '123456789012/global',
                                                                                                   'account_id': '123456789012',
                                                                                                   'global': True,
                                                                                                   'status': 'collected',
                                                                                                   'items': [{'Arn': 'arn:aws:iam::123456789012:user/alice',
                                                                                                              'AttachedManagedPolicies': [],
                                                                                                              'UserPolicyList': [],
                                                                                                              '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails',
                                                                                                                              'native_response_complete': True},
                                                                                                              'UserName': 'alice'}]}]}},
                                                      'fail_index': {'context': {'scope': '123456789012/us-east-1'},
                                                                     'collections': {'iam_user': [{'type': 'iam_user',
                                                                                                   'scope': '123456789012/global',
                                                                                                   'account_id': '123456789012',
                                                                                                   'global': True,
                                                                                                   'status': 'collected',
                                                                                                   'items': [{'Arn': 'arn:aws:iam::123456789012:user/alice',
                                                                                                              'AttachedManagedPolicies': [],
                                                                                                              'UserPolicyList': [{'PolicyName': 'inline',
                                                                                                                                  'PolicyDocument': {'Statement': [{'Effect': 'Allow',
                                                                                                                                                                    'Action': '*',
                                                                                                                                                                    'Resource': '*'}]}}],
                                                                                                              '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails',
                                                                                                                              'native_response_complete': True},
                                                                                                              'UserName': 'alice'}]}]}},
                                                      'missing': {},
                                                      'malformed': None}}
