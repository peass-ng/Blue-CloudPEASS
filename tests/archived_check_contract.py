"""Test-only entry points for explicitly selected archived check contracts.

These wrappers keep old evaluator/collector fixture assertions without admitting
retired controls to automatic product scans. Calls without explicit archived IDs
run through the unmodified engine and native-only manifest.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch


def _ids(selected):
    if isinstance(selected, str):
        return {selected}
    if not isinstance(selected, (list, tuple, set, frozenset)):
        return set()
    return {value if isinstance(value, str) else getattr(value, "id", None)
            for value in selected} - {None}


@contextmanager
def _archived_scope(selected):
    from peaso.checks import native_only

    archived = native_only.exclusions()
    requested = _ids(selected) & archived.keys()
    if not requested:
        yield
        return
    # Preserve all other exclusions, including those for another provider.
    remaining = {ident: entry for ident, entry in archived.items() if ident not in requested}
    with patch.object(native_only, "exclusions", return_value=remaining):
        from peaso.checks import CHECKS
        needs_host_metadata = any(check.id in requested and
                                  (check.kind == "file_metadata" or "file_metadata" in check.dependencies)
                                  for check in CHECKS)
        if needs_host_metadata:
            original_inventory_scope = native_only.external_inventory_types
            with patch.object(native_only, "external_inventory_types",
                              side_effect=lambda provider: original_inventory_scope(provider) - {"file_metadata"}):
                yield
        else:
            yield


def evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None, timings=None,
                      include_not_applicable=True, related_snapshots=None):
    from peaso import engine

    with _archived_scope(checks):
        return engine.evaluate_snapshot(snapshot, categories, checks, frameworks, timings,
                                        include_not_applicable, related_snapshots)


def plan_collection(request):
    from peaso import engine

    with _archived_scope(request.get("checks") if isinstance(request, dict) else None):
        return engine.plan_collection(request)


def collect_snapshot(request):
    from peaso import engine

    with _archived_scope(request.get("checks") if isinstance(request, dict) else None):
        return engine.collect_snapshot(request)


def run_scan(request):
    from peaso import engine

    with _archived_scope(request.get("checks") if isinstance(request, dict) else None):
        return engine.run_scan(request)


def archived_registry(checks):
    """Return the registry for explicit archived fixture IDs only."""
    from peaso import engine

    with _archived_scope(checks):
        return engine._registry()
