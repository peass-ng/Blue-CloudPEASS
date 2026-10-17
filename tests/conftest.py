"""Keep unpublished check registrations out of the full-suite registry."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.compliance_draft_isolation import (CHILD_FILE_ENV, DRAFT_TEST_MODULES,
    STAGED_UNSELECTED_TEST_MODULES, staged_modules_unregistered, staged_registry, unpublished_check_imports)


TESTS_DIR = Path(__file__).resolve().parent


def _requested_draft_files(config) -> list[str]:
    requested = []
    for arg in config.args:
        path = Path(str(arg).split("::", 1)[0]).resolve()
        if path.parent == TESTS_DIR and path.name in DRAFT_TEST_MODULES:
            requested.append(path.name)
    return requested


def _requested_staged_files(config) -> list[str]:
    return [path.name for arg in config.args
            if (path := Path(str(arg).split("::", 1)[0]).resolve()).parent == TESTS_DIR
            and path.name in STAGED_UNSELECTED_TEST_MODULES]


def _selected_path(path: Path, config) -> bool:
    """Pytest may ask about siblings outside an explicitly requested file."""
    if not config.args:
        return True
    for arg in config.args:
        selected = Path(str(arg).split("::", 1)[0]).resolve()
        if path == selected or (selected.is_dir() and selected in path.parents):
            return True
    return False


def pytest_configure(config):
    requested = _requested_draft_files(config)
    staged = _requested_staged_files(config)
    child_file = os.environ.get(CHILD_FILE_ENV)
    if child_file is not None:
        if child_file not in DRAFT_TEST_MODULES or len(config.args) != 1 or requested != [child_file]:
            raise pytest.UsageError(
                f"{CHILD_FILE_ENV} requires exactly its named draft test file as the sole pytest selection"
            )
    elif requested and (len(config.args) != 1 or len(requested) != 1):
        raise pytest.UsageError(
            "An explicit draft test mixed with other selections would contaminate the runtime registry; "
            "run each draft file alone or run the full suite through test_peaso_compliance_draft_isolation.py"
        )
    elif staged and (len(config.args) != 1 or len(staged) != 1):
        raise pytest.UsageError("An explicitly selected staged registrar test must be the sole pytest selection")


def pytest_ignore_collect(collection_path: Path, config):
    path = Path(collection_path).resolve()
    if path.suffix != ".py" or not path.name.startswith("test_") or TESTS_DIR not in path.parents:
        return None
    if not _selected_path(path, config):
        return None
    if path.parent == TESTS_DIR and path.name in STAGED_UNSELECTED_TEST_MODULES:
        expected = set(STAGED_UNSELECTED_TEST_MODULES[path.name])
        if unpublished_check_imports(path) != expected or not staged_modules_unregistered(expected):
            raise pytest.UsageError(f"Staged-unselected registrar boundary drift in {path.name}")
        return None if _requested_staged_files(config) == [path.name] else True
    if path.parent != TESTS_DIR or path.name not in DRAFT_TEST_MODULES:
        if unpublished_check_imports(path):
            raise pytest.UsageError(
                f"Unreviewed unpublished-check import in {path}; add the exact file/module to the "
                "reviewed draft-isolation allowlist before collecting it"
            )
        return None
    imported = unpublished_check_imports(path)
    if imported != {DRAFT_TEST_MODULES[path.name]}:
        raise pytest.UsageError(f"Draft-isolation allowlist drift in {path.name}: {sorted(imported)}")
    child_file = os.environ.get(CHILD_FILE_ENV)
    if child_file == path.name or (child_file is None and _requested_draft_files(config) == [path.name]):
        return None
    return True


def pytest_sessionstart(session):
    from tests.release_test_inputs import restore_missing_inputs

    restored = restore_missing_inputs(TESTS_DIR.parent)
    if restored:
        session.config.add_cleanup(lambda: [path.unlink(missing_ok=True) for path in restored])
    selected = _requested_staged_files(session.config)
    drafts = _requested_draft_files(session.config)
    modules = STAGED_UNSELECTED_TEST_MODULES[selected[0]] if selected else [DRAFT_TEST_MODULES[drafts[0]]] if drafts else []
    if modules:
        sandbox = staged_registry(modules)
        sandbox.__enter__()
        session.config.add_cleanup(lambda: sandbox.__exit__(None, None, None))
