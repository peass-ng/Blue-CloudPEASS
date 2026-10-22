"""Reverse only the reviewed provider/label metadata changes for the retained epoch."""
import gzip,hashlib,json
from pathlib import Path
FIXTURE_SHA256 = '6bca40dc5a533a46e1973cb33ee78350cbaf62bf3d812049909a4459f1d05336'

def predecessor_catalog(value):
    raw=(Path(__file__).with_name('fixtures')/'provider_group_catalog_history_20261021.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==FIXTURE_SHA256
    receipt=json.loads(gzip.decompress(raw))
    assert receipt['schema_version']==1
    digest=lambda obj:hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    for archived in receipt['archived_analysis_checks']:
        row = archived['row']
        assert not any(c['id'] == row['id'] for c in value['checks'])
        offset = next(i for i,c in enumerate(value['checks']) if c['id'] == archived['before_id'])
        value['checks'].insert(offset, row)
    checks={row['id']:row for row in value['checks']}
    assert len(checks)==len(value['checks'])
    for cid,expected in receipt['added_checks'].items():
        assert cid in checks
        row={k:v for k,v in checks[cid].items() if k!='clarity_evaluation_contract'}
        assert digest(row)==expected, 'New provider catalog row changed: '+cid
    value['checks']=[row for row in value['checks'] if row['id'] not in receipt['added_checks']]
    for change in receipt['changes']:
        path=change['path']
        if path[0]=='checks':current=checks[path[1]];keys=path[2:]
        else:current=value;keys=path
        for key in keys[:-1]:current=current[key]
        assert digest(current[keys[-1]])==change['after_sha256'], 'Provider catalog delta changed: '+repr(path)
        current[keys[-1]]=change['before']
    return value


# Exact current-main composition, retaining the original provider fixture and
# every original predecessor digest above. Only metadata is reconstructed.
COMBINED_FIXTURE_SHA256 = 'bddd5cfec261e1833ac4e0c23310e1423a4b443723aa95a57f4a5264b300270b'
ARCHIVED_PRIVESC_SUCCESSOR_SHA256 = '2803c16fd0b863144e7f36513ea3f52bd83412ef1b971efc9294dd46e093af66'
PRIOR_CURRENT_PRIVESC_SUCCESSOR_SHA256 = 'b9ce0d2d49427c843737d495cd357a082e7b6cb090b9809c2f9b874093ac2b2f'

def combined_predecessor_catalog(value):
    from copy import deepcopy
    raw=(Path(__file__).with_name('fixtures')/'combined_iam_network_provider_catalog_successor_20261022.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==COMBINED_FIXTURE_SHA256
    receipt=json.loads(gzip.decompress(raw))
    assert receipt['schema_version']==1
    digest=lambda obj:hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    # New main changes the reviewed privilege-path binding/catalog and AWS fact inventory.
    # Reverse those four fields before verifying the unchanged combined fixture.
    archived_raw=(Path(__file__).with_name('fixtures')/f'current_privesc_catalog_successor_20261022-{ARCHIVED_PRIVESC_SUCCESSOR_SHA256}.json.gz').read_bytes()
    assert hashlib.sha256(archived_raw).hexdigest()==ARCHIVED_PRIVESC_SUCCESSOR_SHA256
    archived=json.loads(gzip.decompress(archived_raw))
    prior_raw=(Path(__file__).with_name('fixtures')/f'current_privesc_catalog_successor_20261022-{PRIOR_CURRENT_PRIVESC_SUCCESSOR_SHA256}.json.gz').read_bytes()
    assert hashlib.sha256(prior_raw).hexdigest()==PRIOR_CURRENT_PRIVESC_SUCCESSOR_SHA256
    prior=json.loads(gzip.decompress(prior_raw))
    successor_raw=(Path(__file__).with_name('fixtures')/'current_privesc_catalog_successor_20261022.json.gz').read_bytes()
    assert hashlib.sha256(successor_raw).hexdigest()=='4e8e649a376c118a0f8e94690abf2bd3eeaed006f94e66409155117e8ae50b83'
    successor=json.loads(gzip.decompress(successor_raw))
    assert set(successor['top_changes'])=={'privesc_catalog','privesc_techniques','inventories','inventory_coverage'}
    assert successor['before_catalog_sha256']==archived['before_catalog_sha256']
    assert {key: change['before'] for key,change in successor['top_changes'].items()}=={
        key: change['before'] for key,change in archived['top_changes'].items()}
    assert prior['before_catalog_sha256']==successor['before_catalog_sha256']
    assert {key: change['before'] for key,change in prior['top_changes'].items()}=={
        key: change['before'] for key,change in successor['top_changes'].items()}
    candidate=deepcopy(value)
    for row in candidate['checks']:row.pop('clarity_evaluation_contract',None)
    assert digest(candidate)==successor['after_catalog_sha256'], 'Combined current catalog changed'
    for key,change in successor['top_changes'].items():
        assert digest(value[key])==change['after_sha256']
        value[key]=deepcopy(change['before'])
    candidate=deepcopy(value)
    for row in candidate['checks']:row.pop('clarity_evaluation_contract',None)
    assert digest(candidate)==successor['before_catalog_sha256']==receipt['after_catalog_sha256']
    normalized=deepcopy(value)
    for row in normalized['checks']:row.pop('clarity_evaluation_contract',None)
    assert digest(normalized)==receipt['after_catalog_sha256'], 'Combined current catalog changed'
    checks={row['id']:row for row in value['checks']}
    assert len(checks)==len(value['checks'])
    for cid,expected in receipt['added_checks'].items():
        row={k:v for k,v in checks[cid].items() if k!='clarity_evaluation_contract'}
        assert digest(row)==expected, 'Combined added check changed: '+cid
        del checks[cid]
    for cid,change in receipt['changed_checks'].items():
        row=checks[cid]
        assert digest({k:v for k,v in row.items() if k!='clarity_evaluation_contract'})==change['after_sha256']
        restored=deepcopy(change['before'])
        if 'clarity_evaluation_contract' in row:restored['clarity_evaluation_contract']=row['clarity_evaluation_contract']
        checks[cid]=restored
    assert set(checks)==set(receipt['before_check_order'])
    value['checks']=[checks[cid] for cid in receipt['before_check_order']]
    for key,change in receipt['top_changes'].items():
        assert digest(value[key])==change['after_sha256']
        value[key]=deepcopy(change['before'])
    normalized=deepcopy(value)
    for row in normalized['checks']:row.pop('clarity_evaluation_contract',None)
    assert digest(normalized)==receipt['before_catalog_sha256'], 'Combined catalog predecessor changed'
    return value
