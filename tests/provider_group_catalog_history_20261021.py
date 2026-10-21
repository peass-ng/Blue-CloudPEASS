"""Reverse only the reviewed provider/label metadata changes for the retained epoch."""
import gzip,hashlib,json
from pathlib import Path
FIXTURE_SHA256 = '0cc8bcfdb5ad25ed9c6b20470bd281c225af96ef4b1b91e43d82f8a217b45d84'

def predecessor_catalog(value):
    raw=(Path(__file__).with_name('fixtures')/'provider_group_catalog_history_20261021.json.gz').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==FIXTURE_SHA256
    receipt=json.loads(gzip.decompress(raw))
    assert receipt['schema_version']==1
    digest=lambda obj:hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
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
