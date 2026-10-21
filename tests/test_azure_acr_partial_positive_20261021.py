"""Preserve typed ACR HIGH findings when scan coverage remains incomplete."""
from tests.test_azure_acr_image_vulnerabilities_20261021 import (
    proposal, collect, fake_runner, index,
)

def _partial_runner(image, manifest, config, layers, **kwargs):
    result = fake_runner('FAIL')(image, manifest, config, layers, **kwargs)
    result.update(complete=False, scan_complete=False, coverage_status='UNKNOWN', database={'fresh': False})
    return result

def test_partial_bound_high_retains_fail_and_images_findings(proposal, monkeypatch, tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    from peaso.image_findings import build_report
    acr, azure, native, check = proposal
    result = collect(proposal, monkeypatch, tmp_path, runner=_partial_runner)
    marker = result['rows'][0][native.MARKER]
    assert result['status'] == 'FAIL' and result['complete'] is False
    assert marker['status'] == 'FAIL' and marker['complete'] is False
    assert result['observations'] == [marker['observation']]
    report = build_report(result['observations'], selected=True)
    assert report['coverage'] == 'UNKNOWN' and (not report['complete'])
    assert len(report['rows']) == 1 and report['rows'][0]['severity'] == 'HIGH'
    status, evidence = check.evaluate(*index(native, result, existing.SCOPE))
    assert status == 'FAIL' and evidence['Coverage'] == 'UNKNOWN'
    assert len(evidence['Vulnerabilities']) == 1
    assert check.DECLARATION['allow_incomplete_failure'] is True

def test_partial_registered_predicate(proposal, monkeypatch, tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    import peaso.checks as registry
    acr, azure, native, check = proposal
    result = collect(proposal, monkeypatch, tmp_path, runner=_partial_runner)
    before = list(registry.CHECKS)
    try:
        check.install()
        registered, = [c for c in registry.CHECKS if c.id == native.CHECK]
        assert registered.allow_incomplete_failure is True
        assert registered.evaluate(*index(native, result, existing.SCOPE))[0] == 'FAIL'
    finally:
        registry.CHECKS[:] = before

def test_stale_empty_and_foreign_image_stay_unknown(proposal, monkeypatch, tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr, azure, native, check = proposal
    result = collect(proposal, monkeypatch, tmp_path, runner=fake_runner('UNKNOWN'))
    assert result['status'] == 'UNKNOWN' and result['observations'] in ([], [None])
    assert check.evaluate(*index(native, result, existing.SCOPE))[0] == 'UNKNOWN'

    def foreign(image, manifest, config, layers, **kwargs):
        result = _partial_runner(image, manifest, config, layers, **kwargs)
        result['image'] = dict(image, manifest_digest='sha256:' + 'f' * 64)
        return result
    result = collect(proposal, monkeypatch, tmp_path, runner=foreign)
    assert result['status'] == 'UNKNOWN'
    assert check.evaluate(*index(native, result, existing.SCOPE))[0] == 'UNKNOWN'

def test_malformed_partial_finding_stays_unknown(proposal, monkeypatch, tmp_path):
    from tests import test_azure_acr_image_secret_review_20261020 as existing
    acr, azure, native, check = proposal

    def malformed(image, manifest, config, layers, **kwargs):
        result = _partial_runner(image, manifest, config, layers, **kwargs)
        result['findings'][0]['severity'] = 'LOW'
        return result
    result = collect(proposal, monkeypatch, tmp_path, runner=malformed)
    assert result['status'] == 'UNKNOWN'
    assert check.evaluate(*index(native, result, existing.SCOPE))[0] == 'UNKNOWN'
