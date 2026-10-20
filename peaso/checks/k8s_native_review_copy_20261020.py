"""Exact concise copy successors; original signed rows and source pins remain."""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path

@lru_cache(maxsize=1)
def _rows():
    document=json.loads(Path(__file__).with_suffix('.json').read_text())
    if document.get('schema_version')!=1:raise ValueError('Unrecognized Kubernetes copy review')
    return document['checks']

def reviewed_fields(cid,kind,predecessor):
    row=_rows().get(cid,{}).get(kind)
    if row is None:return deepcopy(predecessor)
    digest=hashlib.sha256(json.dumps(predecessor,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    if digest!=row['predecessor_sha256']:raise ValueError('Reviewed Kubernetes copy predecessor changed: '+cid)
    return {**deepcopy(predecessor),**deepcopy(row['fields'])}
