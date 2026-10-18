"""Explicit externally authorized inert service inventory; no runtime discovery."""
import copy,hashlib,json
CID='azure.other.nsg_port_protocol_assignment'
S='/subscriptions/sub'
NOW='2026-10-12T00:00:00Z'
NSG=S+'/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n'
def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
def fixture(*,actual='https',bare=False):
    nsg={'id':NSG,'properties':{'securityRules':[],'defaultSecurityRules':[]}}
    path={'id':NSG+'/effectiveInternetPaths/tcp443','parent_id':NSG,'properties':{'protocol':'Tcp','destinationPort':443,'worldSource':True,'allowed':True}}
    capture={'scope':S,'created_at':NOW}
    binding=digest({'nsg':nsg,'path':path,'capture':capture})
    observation={'sourceId':'authorized-workload-inventory','method':'passive-service-inventory','observedAt':'2026-10-11T23:00:00Z',
       'scope':S,'checkId':CID,'nsgId':NSG,'pathId':path['id'],'protocol':'Tcp','port':443,'service':actual,
       'capture':capture,'snapshotSha256':binding,'artifactSha256':'a'*64,'readOnly':True}
    measurement={'id':NSG+'/serviceMeasurements/tcp443','parent_id':NSG,'path_id':path['id'],
       'properties':{'protocol':'Tcp','port':443,'measuredService':actual,'ianaAssignedService':'https'}}
    authority={'scope':S,'checkId':CID,'documentId':'independent-owner-approved-inventory-records','authorizedBy':'security-owner',
       'approvedAt':'2026-10-11T22:00:00Z','expiresAt':'2026-10-13T00:00:00Z','maxAgeSeconds':3600,
       'approvedSourceIds':['authorized-workload-inventory'],'approvedMethods':['passive-service-inventory'],
       'approvedSnapshotSha256s':[binding],'approvedObservationSha256s':[digest(observation)]}
    if not bare:measurement['properties']['observation']=observation
    collections={'nsg':[(S,[nsg])],'nsg_effective_internet_path':[(S,[path])],'nsg_service_measurement':[(S,[measurement])]}
    return collections,{'serviceObservationAuthority':authority}
def index(collections,policy):
    return {'context':{'provider':'azure','scope':S,'created_at':NOW,'metadata':{'compliance_policy':{'sw31':policy}}},
      'collections':{k:[{'scope':s,'status':'collected' if rows else 'empty','items':copy.deepcopy(rows)} for s,rows in v] for k,v in collections.items()},
      **{k:[{'scope':s,'data':copy.deepcopy(row)} for s,rows in v for row in rows] for k,v in collections.items()}}


def authorize_fixture_index(index):
    """Attach independently approved SYNTHETIC inventory to this exact fixture.

    This test-only function is not a collector or an authorization mechanism.
    """
    from datetime import datetime,timedelta
    context=index['context'];scope=context['scope'];created=context['created_at']
    current=datetime.fromisoformat(created.replace('Z','+00:00'))
    authority=fixture()[1]['serviceObservationAuthority']
    authority.update(scope=scope,approvedAt=(current-timedelta(hours=2)).isoformat(),expiresAt=(current+timedelta(days=1)).isoformat(),approvedSnapshotSha256s=[],approvedObservationSha256s=[])
    capture={'scope':scope,'created_at':created}
    for field in ('credential_context_id','customer_context_id'):
        if field in context['metadata']:capture[field]=context['metadata'][field]
    nsgs={r['data']['id']:r['data'] for r in index['nsg']}
    paths={r['data']['id']:r['data'] for r in index['nsg_effective_internet_path']}
    for wrapper in index['nsg_service_measurement']:
        m=wrapper['data'];path=paths[m['path_id']];nsg=nsgs[m['parent_id']];props=m['properties']
        binding=digest({'nsg':nsg,'path':path,'capture':capture})
        observation={'sourceId':'authorized-workload-inventory','method':'passive-service-inventory','observedAt':(current-timedelta(hours=1)).isoformat(),
          'scope':scope,'checkId':CID,'nsgId':nsg['id'],'pathId':path['id'],'protocol':props['protocol'],'port':props['port'],'service':props['measuredService'],
          'capture':capture,'snapshotSha256':binding,'artifactSha256':'a'*64,'readOnly':True}
        props['observation']=observation
        authority['approvedSnapshotSha256s'].append(binding);authority['approvedObservationSha256s'].append(digest(observation))
        for envelope in index['collections']['nsg_service_measurement']:
            for row in envelope['items']:
                if row['id']==m['id']:row['properties']['observation']=copy.deepcopy(observation)
    context['metadata']['compliance_policy']['sw31']['serviceObservationAuthority']=authority
    return index
