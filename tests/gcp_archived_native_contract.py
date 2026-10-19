"""Historical GCP predicate fixtures, explicitly outside automated scan selection.

Only the three owner-evidence controls retired from automatic scans are admitted
here. This calls their registered functions directly: no engine selection,
registry, exclusions, collector configuration or hosted validation is patched.
"""
from peaso.checks import CHECKS
from peaso.checks.facts import MemoIndex
from peaso.engine import _index
from peaso.snapshot import freeze, resources, validate

ARCHIVED_GCP_IDS=frozenset({'gcp_pci_iam_policy_ca1281da7ab2','gcp_pci_iam_policy_9a8ce875703d','gcp_c5_sbom'})


def archived_check(check_id):
    if check_id not in ARCHIVED_GCP_IDS:
        raise ValueError('This fixture helper supports only three explicit historical GCP contracts')
    return next(check for check in CHECKS if check.id==check_id)


def historical_collection_types(check_id):
    """Explicit historical fixture inventories, not a product collection plan."""
    return list(archived_check(check_id).dependencies)


def evaluate_historical_snapshot(snapshot,*,checks,categories=None,include_not_applicable=True):
    snapshot=validate(snapshot,read_only=True)
    if snapshot['provider']!='gcp':raise ValueError('Historical GCP fixtures only')
    selected=[archived_check(cid) for cid in checks]
    inventory=resources(snapshot);index=_index(snapshot,inventory);findings=[]
    for check in selected:
        for resource in inventory:
            if resource['type']!=check.kind:continue
            scope=resource['scope']
            # GCP snapshot dependencies stay within the exact selected scope;
            # preserve raw authoritative envelope order and duplicate items.
            selected_collections={kind:[c for c in rows if c['scope']==scope]
                                  for kind,rows in index['collections'].items()}
            scoped=MemoIndex({kind:[r for r in rows if r['scope']==scope]
                              for kind,rows in index.items() if kind!='collections'})
            scoped['collections']=selected_collections
            context=freeze({'provider':'gcp','scope':scope,'_scope':scope,
                            'created_at':snapshot['created_at'],'snapshot_id':snapshot['snapshot_id'],
                            'metadata':snapshot.get('metadata',{})})
            scoped['context']=scoped['_snapshot']=context
            status,evidence=check.evaluate(resource['data'],scoped)
            if include_not_applicable or status not in ('NOT_APPLICABLE','EMPTY'):
                findings.append({'provider':'gcp','check_id':check.id,'resource_id':resource['id'],
                                 'scope':scope,'status':status,'evidence':evidence})
    return {'findings':findings}
