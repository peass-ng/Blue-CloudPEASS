"""Exact reviewed historical imports preserve the unpublished registrar boundary."""

import hashlib
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from tests import compliance_draft_isolation as boundary, conftest as draft_hook


HISTORICAL = "azure_nsp_query_cmk_production_admission_20261020"
SUCCESSOR = "azure_nsp_query_cmk_production_tde_successor_20261020"
TESTS = boundary.CHECKS_DIR.parents[1] / "tests"


@pytest.fixture(autouse=True)
def fresh_classification_cache():
    boundary._unpublished_module.cache_clear()
    yield
    boundary._unpublished_module.cache_clear()


def test_exact_historical_mapping_matches_successor_reviewed_source():
    assert set(boundary.PUBLISHED_HISTORICAL_SUCCESSORS) == {HISTORICAL}
    successor, digest = boundary.PUBLISHED_HISTORICAL_SUCCESSORS[HISTORICAL]
    assert successor == SUCCESSOR
    assert successor in boundary.PUBLISHED_CHECK_MODULES
    receipt = json.loads((boundary.CHECKS_DIR / (SUCCESSOR + ".json")).read_bytes())
    assert receipt["predecessor_files"]["peaso/checks/" + HISTORICAL + ".py"] == digest
    assert hashlib.sha256((boundary.CHECKS_DIR / (HISTORICAL + ".py")).read_bytes()).hexdigest() == digest


def test_full_suite_hook_accepts_actual_compatibility_test_without_loading_registrars(monkeypatch):
    monkeypatch.delenv(boundary.CHILD_FILE_ENV, raising=False)
    target = TESTS / "test_azure_nsp_tde_admission_compatibility_20261020.py"
    before_modules = dict(sys.modules)
    before_checks = tuple(boundary.peaso.checks.CHECKS)
    before_aliases = dict(boundary.peaso.checks.CHECK_ALIASES)
    assert boundary.unpublished_check_imports(target) == set()
    assert draft_hook.pytest_ignore_collect(target, SimpleNamespace(args=[str(TESTS)])) is None
    assert dict(sys.modules) == before_modules
    assert tuple(map(id, boundary.peaso.checks.CHECKS)) == tuple(map(id, before_checks))
    assert boundary.peaso.checks.CHECK_ALIASES == before_aliases


@pytest.mark.parametrize("syntax", [
    "from peaso.checks import {name} as historical\n",
    "from peaso.checks.{name} import reviewed_inputs\n",
    "import peaso.checks.{name} as historical\n",
    "import importlib\nhistorical = importlib.import_module('peaso.checks.{name}')\n",
    "import importlib\nMODULE = 'peaso.checks.{name}'\nhistorical = importlib.import_module(MODULE)\n",
])
def test_exact_reviewed_alias_is_accepted_for_supported_import_syntax(tmp_path, syntax):
    target = tmp_path / "test_import.py"
    target.write_text(syntax.format(name=HISTORICAL))
    assert boundary.unpublished_check_imports(target) == set()


def test_historical_alias_requires_admitted_successor(tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, "PUBLISHED_CHECK_MODULES",
                        boundary.PUBLISHED_CHECK_MODULES - {HISTORICAL, SUCCESSOR})
    monkeypatch.setattr(draft_hook, "TESTS_DIR", tmp_path)
    target = tmp_path / "test_import.py"
    target.write_text(f"from peaso.checks import {HISTORICAL}\n")
    assert boundary.unpublished_check_imports(target) == {HISTORICAL}
    with pytest.raises(pytest.UsageError, match="Unreviewed unpublished-check import"):
        draft_hook.pytest_ignore_collect(target, SimpleNamespace(args=[str(tmp_path)]))


@pytest.mark.parametrize("source", [None, "# modified historical helper\n",
                                       "@register('unreviewed')\ndef check(): pass\n"])
def test_historical_alias_requires_exact_predecessor_bytes(tmp_path, monkeypatch, source):
    monkeypatch.setattr(boundary, "PUBLISHED_CHECK_MODULES", boundary.PUBLISHED_CHECK_MODULES - {HISTORICAL})
    monkeypatch.setattr(boundary, "CHECKS_DIR", tmp_path)
    monkeypatch.setattr(draft_hook, "TESTS_DIR", tmp_path)
    if source is not None:
        (tmp_path / (HISTORICAL + ".py")).write_text(source)
    target = tmp_path / "test_import.py"
    target.write_text(f"from peaso.checks import {HISTORICAL}\n")
    assert boundary.unpublished_check_imports(target) == {HISTORICAL}
    with pytest.raises(pytest.UsageError, match="Unreviewed unpublished-check import"):
        draft_hook.pytest_ignore_collect(target, SimpleNamespace(args=[str(tmp_path)]))


@pytest.mark.parametrize("name", [HISTORICAL + "_extra", "azure_unreviewed_admission_20261020",
                                  "azure_nsp_query_cmk_production_admission_20261021"])
def test_similar_or_late_loaded_registrars_still_reject(tmp_path, monkeypatch, name):
    monkeypatch.setattr(boundary, "CHECKS_DIR", tmp_path)
    monkeypatch.setattr(draft_hook, "TESTS_DIR", tmp_path)
    # Late sys.modules entries and package aliases cannot extend startup admission.
    module = ModuleType("peaso.checks." + name)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(boundary.peaso.checks, name, module, raising=False)
    (tmp_path / (name + ".py")).write_text("@register('unreviewed')\ndef check(): pass\n")
    target = tmp_path / "test_import.py"
    target.write_text(f"from peaso.checks import {name}\n")
    assert boundary.unpublished_check_imports(target) == {name}
    with pytest.raises(pytest.UsageError, match="Unreviewed unpublished-check import"):
        draft_hook.pytest_ignore_collect(target, SimpleNamespace(args=[str(tmp_path)]))


def test_explicit_inactive_registrar_boundary_takes_precedence(monkeypatch):
    monkeypatch.setattr(boundary, "INACTIVE_REGISTRAR_MODULES",
                        boundary.INACTIVE_REGISTRAR_MODULES | {HISTORICAL})
    assert boundary._unpublished_module(HISTORICAL) is True
    assert all(boundary._unpublished_module(name) for name in boundary.INACTIVE_REGISTRAR_MODULES)
