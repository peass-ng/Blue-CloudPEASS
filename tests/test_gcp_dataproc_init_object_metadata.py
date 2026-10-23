"""Dataproc init-action reads retain only bounded exact object metadata."""

import pytest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


_PATH = Path(__file__).resolve().parents[1] / 'peaso/collectors/gcp_dataproc_init_objects.py'
_SPEC = spec_from_file_location('dataproc_init_objects_projection', _PATH)
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
metadata = _MODULE.metadata
references = _MODULE.references


def test_only_exact_unpinned_init_references_are_selected():
    cluster = {'config': {'initializationActions': [
        {'executableFile': 'gs://bucket/start.sh'},
        {'executableFile': 'gs://bucket/start.sh#123'},
        {'executableFile': 'https://example.com/start.sh'},
    ]}}
    assert references(cluster) == {'gs://bucket/start.sh': ('bucket', 'start.sh')}
    cluster['config']['initializationActions'] *= 12
    assert references(cluster) is None


def test_metadata_projects_only_live_generation_and_replacement_controls():
    row = {'bucket': 'bucket', 'name': 'start.sh', 'generation': '123',
           'temporaryHold': False, 'eventBasedHold': True,
           'retention': {'retainUntilTime': '2030-01-01T00:00:00Z'},
           'metadata': {'secret': 'discard-me'}}
    result = metadata(row, 'bucket', 'start.sh')
    assert result['eventBasedHold'] is True
    assert result['retainUntilTime'] == '2030-01-01T00:00:00Z'
    assert 'discard-me' not in repr(result)
    with pytest.raises(ValueError):
        metadata(row, 'different-bucket', 'start.sh')
