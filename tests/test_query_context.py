import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('query_context', Path('docker/query_context.py'))
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)


def test_image_scope_preserves_controls_and_escapes_sql_and_hcl():
    text = '\n'.join('control "' + name + '" {\n sql = replace(local.' + template + ', "__TABLE_NAME__", "gcp_compute_image")\n}\n' for name, template in [('compute_image_policy_prohibit_public_access','iam_policy_public_sql'), ('compute_image_policy_shared_access','iam_policy_shared_access_sql')])
    project = "project'${token}%{value}"
    modified, applied = context._scope_image_controls(text, project)
    assert len(applied) == 2
    assert modified.count("source_project = 'project''$${token}%%{value}'") == 2
    assert modified.count('control "') == 2


def test_pinned_image_query_change_is_not_silently_ignored():
    with pytest.raises(ValueError, match='Pinned image policy'):
        context._scope_image_controls('control "compute_image_policy_shared_access" {\n sql = "changed"\n}\n', 'selected-project')


def test_inspector_query_change_is_not_silently_ignored():
    with pytest.raises(ValueError, match='Pinned Inspector Classic'):
        context._inspector2_sql('select * from changed_table')


def test_missing_image_controls_stop_the_suite(tmp_path):
    directory = tmp_path / 'gcp-perimeter'
    directory.mkdir()
    with pytest.raises(ValueError, match='Pinned image policy controls changed'):
        context.prepare_query_context(directory, 'gcp', project='selected-project')
