"""The existing private source owner binds cohort execution, not only file bytes."""
import pytest

from peaso.checks import private_secret_shared_source_successor_20261021 as owner
from peaso import secret_scanning_batch, secret_scanning_cohort
from peaso.collectors import aws_lambda_environment_secret_indicators as lambda_source
from peaso.collectors import aws_image_layer_pipeline_20261022 as layer_pipeline
from peaso.collectors import aws_image_vulnerability_native_20261021 as image_native


def test_content_cohort_current_source_and_execution_bindings():
    owner._private_self()


@pytest.mark.parametrize('module,name', [
    (secret_scanning_cohort.ContentCohort, 'output'),
    (secret_scanning_batch, 'prepared_output'),
    (lambda_source, 'collect_selected'),
    (layer_pipeline, 'download_layers'),
    (image_native, '_scan_bound'),
])
def test_content_cohort_rejects_rebound_callable(monkeypatch, module, name):
    original = getattr(module, name)
    monkeypatch.setattr(module, name, lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match='Content cohort executing callable changed'):
        owner._private_self()
    monkeypatch.setattr(module, name, original)


def test_content_cohort_rejects_rebound_import(monkeypatch):
    monkeypatch.setattr(secret_scanning_cohort, 'time', object())
    with pytest.raises(RuntimeError, match='Content cohort import changed'):
        owner._private_self()
