"""Inert App Service managed-identity full-GET inputs; no live reads."""
from copy import deepcopy
CID='azure.cis.app_service_entra_registration_enabled'
SCOPE='/subscriptions/sub1'
SITE=SCOPE+'/resourceGroups/rg1/providers/Microsoft.Web/sites/site1'
ITEM={'id':SITE,'kind':'app','type':'Microsoft.Web/sites','properties':{}}
def index(identity,status='collected'):
 detail={'id':SITE+'/identityDetail','parent_id':SITE,'kind':'app','identity':identity,'_provenance':{'representation':'full','source_operation':'get','read_only':True,'api_version':'2025-03-01'}}
 rows={'app_service':[deepcopy(ITEM)],'app_service_identity_detail':[detail] if status=='collected' else []}
 result={'context':{'provider':'azure','scope':SCOPE},'collections':{}}
 for kind,items in rows.items():
  result['collections'][kind]=[{'type':kind,'scope':SCOPE,'status':status if kind=='app_service_identity_detail' else 'collected','items':deepcopy(items)}]
  result[kind]=[{'type':kind,'scope':SCOPE,'provider':'azure','data':deepcopy(row)} for row in items]
 return result
CASES_FRAGMENT={CID:{'pass':deepcopy(ITEM),'pass_index':index({'type':'SystemAssigned','principalId':'12345678-1234-1234-1234-123456789abc'}),
                     'fail':deepcopy(ITEM),'fail_index':index({'type':'None'}),'unknown':deepcopy(ITEM),'unknown_index':index({},'denied'),
                     'missing':{},'malformed':None}}
