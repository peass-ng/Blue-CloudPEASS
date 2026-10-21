"""Offline contract tests for the isolated ACR streaming proposal."""
import base64
import json
import os
import pytest

@pytest.fixture
def proposal():
    from peaso.collectors import azure_acr_image_secret_indicators as source
    from peaso.checks import azure_acr_image_secret_review_20261020 as checks
    return source, checks


def test_raw_and_gzip_layers_above_old_cap(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    for compressed in (False,True):
        payload=existing.TOKEN.encode()+b'\n'+(base64.b64encode(os.urandom(9*1024*1024)) if compressed else b'x'*(9*1024*1024))
        img=existing.image(files=[('application/config.txt',payload)],compressed=compressed)
        assert len(img.wire)>8*1024*1024
        snapshot,_=existing.capture(monkeypatch,img=img)
        assert checks.evaluate(*existing.index_of(snapshot))[0]=='FAIL'
        exported=json.dumps(snapshot)
        assert existing.TOKEN not in exported and 'application/config.txt' not in exported


def test_later_denial_retains_verified_positive(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    img=existing.image(positive='manifest')
    snapshot,_=existing.capture(monkeypatch,img=img,overrides={'layer_blob':existing.Response(b'',403)})
    assert checks.evaluate(*existing.index_of(snapshot))[0]=='FAIL'

@pytest.mark.parametrize('failure',['wrong_digest','truncated','rootfs','denied','disk'])
def test_incomplete_layer_is_unknown_and_cleans_scratch(proposal,monkeypatch,tmp_path,failure):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    import peaso.collectors.azure_acr_image_stream_inspection_20261021 as inspection
    source,checks=proposal
    img=existing.image()
    overrides={}
    if failure=='wrong_digest':
        overrides['layer_blob']=existing.Response(img.wire[:-1]+b'X')
    elif failure=='truncated':
        overrides['layer_blob']=existing.Response(img.wire[:-1])
    elif failure=='rootfs':
        img.config['rootfs']['diff_ids']=[source._sha(b'wrong')]
        img.config_raw=existing.packed(img.config)
        img.manifest['config']['digest']=source._sha(img.config_raw)
        img.manifest['config']['size']=len(img.config_raw)
        img.manifest_raw=existing.packed(img.manifest)
        img.target['digest']=source._sha(img.manifest_raw)
    elif failure=='denied':
        overrides['layer_blob']=existing.Response(b'',403)
    elif failure=='disk':
        monkeypatch.setattr(source.shutil,'disk_usage',lambda path: type('Usage',(),{'free':0})())
    original=inspection.tempfile.TemporaryDirectory
    def owned(*args,**kwargs):
        return original(*args,dir=tmp_path,**kwargs)
    monkeypatch.setattr(inspection.tempfile,'TemporaryDirectory',owned)
    snapshot,_=existing.capture(monkeypatch,img=img,overrides=overrides)
    assert checks.evaluate(*existing.index_of(snapshot))[0]=='UNKNOWN'
    assert list(tmp_path.iterdir())==[]


def test_installed_offline_engines_detect_verified_layer(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    snapshot,_=existing.capture(monkeypatch,img=existing.image(positive='layer'),real=True)
    status,evidence=checks.evaluate(*existing.index_of(snapshot))
    assert status=='FAIL'
    assert {detector['engine'] for detector in evidence['secret_leaks'][0]['detectors']}=={'kingfisher','trufflehog'}

def test_first_verified_layer_positive_survives_second_unavailable(proposal,monkeypatch):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    source,checks=proposal
    img=existing.image(positive='layer')
    second=existing.image(files=[('another.txt',b'ordinary second layer')])
    img.manifest['layers'].append(second.manifest['layers'][0])
    img.config['rootfs']['diff_ids'].append(source._sha(second.layer))
    img.config_raw=existing.packed(img.config)
    img.manifest['config']['digest']=source._sha(img.config_raw)
    img.manifest['config']['size']=len(img.config_raw)
    img.manifest_raw=existing.packed(img.manifest)
    img.target['digest']=source._sha(img.manifest_raw)
    calls=0
    def layer_response():
        nonlocal calls
        calls+=1
        return existing.Response(img.wire if calls==1 else b'',200 if calls==1 else 403)
    snapshot,_=existing.capture(monkeypatch,img=img,overrides={'layer_blob':layer_response})
    status,evidence=checks.evaluate(*existing.index_of(snapshot))
    assert status=='FAIL' and evidence['complete'] is False
    assert calls==1

@pytest.mark.parametrize('positive,expected',[(None,'UNKNOWN'),('manifest','FAIL')])
def test_nested_archive_cannot_produce_clean_result(proposal,monkeypatch,positive,expected):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    import gzip
    source,checks=proposal
    img=existing.image(positive=positive,files=[('bundled.gz',gzip.compress(b'ordinary nested bytes'))])
    snapshot,_=existing.capture(monkeypatch,img=img)
    assert checks.evaluate(*existing.index_of(snapshot))[0]==expected
