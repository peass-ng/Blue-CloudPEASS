"""Inert proposed CASES addition for the one private EASM candidate."""
from copy import deepcopy

CID = 'azure.cis.defender_external_attack_surface_monitoring_easm'
SCOPE = '/subscriptions/00000000-0000-0000-0000-000000000001'
RID = SCOPE + '/resourceGroups/rg/providers/Microsoft.Easm/workspaces/easm1'


def state(status, items):
    return {'context': {'provider': 'azure', 'scope': SCOPE},
            'collections': {'easm_workspace': [{'type': 'easm_workspace', 'scope': SCOPE, 'status': status,
                                                'items': deepcopy(items)}]},
            'easm_workspace': [{'provider': 'azure', 'type': 'easm_workspace', 'scope': SCOPE, 'data': deepcopy(item)}
                               for item in items]}


PASS_ROWS = [{'id': RID, 'properties': {'provisioningState': 'Succeeded'}}]
FAIL_ROWS = [{'id': RID, 'properties': {'provisioningState': 'Failed'}}]
CASES_FRAGMENT = {CID: {'pass': {}, 'fail': {}, 'unknown': {}, 'missing': {}, 'malformed': None,
                        'pass_index': state('collected', PASS_ROWS),
                        'fail_index': state('collected', FAIL_ROWS),
                        'unknown_index': state('denied', [])}}
