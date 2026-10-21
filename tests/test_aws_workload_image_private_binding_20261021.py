"""Private values remain bound to an observed workload and exact image layer."""
from copy import deepcopy
import json
from pathlib import Path

from peaso import secret_evidence
from peaso.collectors import aws_workload_image_secret_native_20261021 as source

FIXTURE=Path(__file__).with_name('fixtures')/'aws_workload_image_secret_native_20261021.json'

def test_private_workload_alias_preserves_ecr_origin_and_rejects_other_asset(monkeypatch):
    case=next(c for c in json.loads(FIXTURE.read_text())['cases'] if c['name']=='fail_secret')
    row=deepcopy(case['item']['WorkloadImageSecretReview']);target=row['selection'];scope=target['scope']
    reference=next(r for r in row['source']['PackageSecretIndicators']['References'] if r.get('Leaks'))
    leak=deepcopy(reference['Leaks'][0]);fingerprint=leak['fingerprint'];layer=reference['LayerDigest'];path=leak['locations'][0]['path']
    value='synthetic-workload-image-private-value'
    original=row['source']['PackageSecretIndicators']['ResourceId']
    workload=case['item']['id'];cipher=secret_evidence.EphemeralCipher();scan='a'*32
    monkeypatch.setattr(source,'collect_scope',lambda *a,**kw:[row])
    def finding(resource,digest=layer):
        safe=deepcopy(leak);safe['locations']=[dict(loc,layer=digest) for loc in safe['locations']]
        return dict(provider='aws',check_id=source.CHECK,status='FAIL',finding_type='secrets',scope=scope,
            resource_id=resource,native_resource_id=resource,evidence={'secret_leaks':[safe]})
    with secret_evidence.capture(cipher,tenant='fixture',scan_id=scan) as sink:
        with secret_evidence.source_context(resource_id=original,scope=scope,layer=layer,check_ids=[source.CHECK]):
            secret_evidence.remember(value,fingerprint,path=path,engine='kingfisher',rule='fixture-rule')
        result=source.collect_collection(object(),object(),{'Account':scope.split('/')[0]},scope.split('/')[1],[target])
        assert result.items[0]['id']==workload
    document=sink.document()
    assert value not in json.dumps(document)
    for resource in [workload,original]:
        details=secret_evidence.details(finding(resource),document,cipher,tenant='fixture',scan_id=scan)
        assert len(details['matches'])==1 and details['matches'][0]['value']==value
    for resource,digest in [(workload+'-other',layer),(workload,'sha256:'+'f'*64)]:
        details=secret_evidence.details(finding(resource,digest),document,cipher,tenant='fixture',scan_id=scan)
        assert not details['matches']
