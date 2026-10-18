"""Inert, tenant-bound CASES for the three private Graph/log-profile candidates."""
from datetime import datetime, timedelta, timezone
from copy import deepcopy

TENANT = '11111111-1111-1111-1111-111111111111'
SCOPE = '/tenants/' + TENANT
SUB = '/subscriptions/22222222-2222-2222-2222-222222222222'
APP = '33333333-3333-3333-3333-333333333333'
SP = '44444444-4444-4444-4444-444444444444'
KEY = '55555555-5555-5555-5555-555555555555'
PROFILE = SUB + '/providers/Microsoft.Insights/logProfiles/default'
APP_ID = 'azure.other.entra_app_secret_age_90'
SP_ID = 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28'
LOG_ID = 'azure.gap.monitor_log_profile_retention_365_days'
NOW = datetime.now(timezone.utc)
STAMP = NOW.isoformat()
PROOF = {'tenant_id': TENANT, 'tenant_verified': True, 'credential_context_id': 'fixture-credential', 'customer_context_id': 'fixture-customer'}


def credential(days):
    return {'keyId': KEY, 'startDateTime': (NOW-timedelta(days=days)).isoformat(), 'endDateTime': (NOW+timedelta(days=365)).isoformat()}


def graph_index(parent_kind, aggregate_kind, member, suffix):
    parent = [] if member is None else [member]
    subject = {'id': SCOPE+'/'+suffix, 'parent_scope': SCOPE, 'member_count': len(parent),
               '_provenance': {**PROOF, 'source_collection': parent_kind, 'read_only': True}}
    parent_env = {'type': parent_kind, 'scope': SCOPE, 'service': 'Microsoft.Graph',
                  'status': 'collected' if parent else 'empty', 'items': deepcopy(parent), '_provenance': deepcopy(PROOF)}
    aggregate_env = {'type': aggregate_kind, 'scope': SCOPE, 'service': 'Microsoft.Graph',
                     'status': 'collected', 'items': [deepcopy(subject)], '_provenance': deepcopy(PROOF)}
    return subject, {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': STAMP,
                                'metadata': deepcopy(PROOF)},
                     'collections': {parent_kind: [parent_env], aggregate_kind: [aggregate_env]},
                     parent_kind: [{'data': deepcopy(row)} for row in parent],
                     aggregate_kind: [{'data': deepcopy(subject)}]}


def graph_case(parent_kind, aggregate_kind, member_id, suffix, days):
    member = {'id': member_id, 'passwordCredentials': [credential(days)], 'keyCredentials': [],
              '_provenance': {**PROOF, 'endpoint': '/v1.0/applications' if parent_kind == 'directory_application' else '/v1.0/servicePrincipals', 'read_only': True}}
    return graph_index(parent_kind, aggregate_kind, member, suffix)


def log_case(days, status='collected'):
    item = {'id': PROFILE, 'type': 'Microsoft.Insights/logProfiles',
            'properties': {'retentionPolicy': {'enabled': True, 'days': days}}}
    index = {'context': {'provider': 'azure', 'scope': SUB},
             'collections': {'monitor_log_profile': [{'type': 'monitor_log_profile', 'scope': SUB, 'status': status,
                                                      'items': [deepcopy(item)] if status == 'collected' else []}]},
             'monitor_log_profile': [{'data': deepcopy(item)}] if status == 'collected' else []}
    return item, index

APP_PASS, APP_PASS_INDEX = graph_case('directory_application', 'application_scope', APP, 'applicationScope', 1)
APP_FAIL, APP_FAIL_INDEX = graph_case('directory_application', 'application_scope', APP, 'applicationScope', 100)
SP_PASS, SP_PASS_INDEX = graph_case('directory_service_principal', 'service_principal_scope', SP, 'servicePrincipalScope', 1)
SP_FAIL, SP_FAIL_INDEX = graph_case('directory_service_principal', 'service_principal_scope', SP, 'servicePrincipalScope', 100)
LOG_PASS, LOG_PASS_INDEX = log_case(365)
LOG_FAIL, LOG_FAIL_INDEX = log_case(364)

def denied_index(index,kind):
    clone=deepcopy(index)
    clone['collections'][kind][0]['status']='denied'
    return clone

CASES_FRAGMENT = {
    APP_ID: {'pass': APP_PASS, 'pass_index': APP_PASS_INDEX, 'fail': APP_FAIL, 'fail_index': APP_FAIL_INDEX,
             'missing': {}, 'malformed': None, 'unknown': APP_PASS,
             'unknown_index': denied_index(APP_PASS_INDEX,'directory_application')},
    SP_ID: {'pass': SP_PASS, 'pass_index': SP_PASS_INDEX, 'fail': SP_FAIL, 'fail_index': SP_FAIL_INDEX,
            'missing': {}, 'malformed': None, 'unknown': SP_PASS,
            'unknown_index': denied_index(SP_PASS_INDEX,'directory_service_principal')},
    LOG_ID: {'pass': LOG_PASS, 'pass_index': LOG_PASS_INDEX, 'fail': LOG_FAIL, 'fail_index': LOG_FAIL_INDEX,
             'missing': {}, 'malformed': None, 'unknown': LOG_PASS,
             'unknown_index': denied_index(LOG_PASS_INDEX,'monitor_log_profile')},
}
