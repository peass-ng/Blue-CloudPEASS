"""Archived fixture isolation; product automatic admission stays excluded."""
from unittest.mock import patch

import pytest

from peaso import engine
from peaso.checks import native_only
from tests import archived_check_contract as archived

FIRST = "aws_resolver_managed_domain_lists_block"
SECOND = "aws_security_logs_central_search"


def test_explicit_archived_selection_only_temporarily_removes_exact_id():
    original = native_only.exclusions()
    assert FIRST in original and SECOND in original
    marker = object()
    with patch.object(engine, "_registry", return_value=marker) as registry:
        def inspect(*_args, **_kwargs):
            current = native_only.exclusions()
            assert FIRST not in current and SECOND in current
            assert engine._registry() is marker
            return "archived"
        with patch.object(engine, "evaluate_snapshot", side_effect=inspect):
            assert archived.evaluate_snapshot({}, checks=[FIRST]) == "archived"
        registry.assert_called_once()
    assert native_only.exclusions() is original
    assert FIRST in original and SECOND in original


def test_default_and_active_selection_keep_real_exclusions():
    original = native_only.exclusions()
    def inspect(*_args, **_kwargs):
        assert native_only.exclusions() is original
        return "active"
    with patch.object(engine, "evaluate_snapshot", side_effect=inspect):
        assert archived.evaluate_snapshot({}) == "active"
        assert archived.evaluate_snapshot({}, checks=["aws.iam.console_mfa"]) == "active"


def test_request_wrappers_restore_on_exception_and_do_not_relax_other_ids():
    original = native_only.exclusions()
    request = {"checks": [FIRST]}
    for name in ("plan_collection", "collect_snapshot", "run_scan"):
        def raise_after_check(_request):
            assert FIRST not in native_only.exclusions()
            assert SECOND in native_only.exclusions()
            raise RuntimeError("probe")
        with patch.object(engine, name, side_effect=raise_after_check):
            with pytest.raises(RuntimeError, match="probe"):
                getattr(archived, name)(request)
        assert native_only.exclusions() is original


def test_file_metadata_whitelist_only_inside_explicit_archived_fixture():
    original = native_only.external_inventory_types
    file_check = "k8s.cis.file_admin_conf_owner"
    with patch.object(engine, "plan_collection", side_effect=lambda request:
                      (native_only.external_inventory_types("k8s"), file_check in native_only.exclusions())):
        assert archived.plan_collection({"checks": [file_check]}) == (frozenset(), False)
        assert archived.plan_collection({"checks": [FIRST]}) == (frozenset({"file_metadata"}), True)
    assert native_only.external_inventory_types is original


def test_every_archived_host_metadata_contract_can_plan_only_in_fixture_scope():
    from peaso.checks import CHECKS, native_only
    from peaso import engine
    from tests.archived_check_contract import plan_collection
    archived = native_only.exclusions()
    for check in CHECKS:
        if check.id not in archived or (check.kind != "file_metadata" and "file_metadata" not in check.dependencies):
            continue
        request = {"connector": {"provider": check.provider}, "checks": [check.id]}
        assert "file_metadata" in plan_collection(request)
        with pytest.raises(ValueError, match="external policy or manual evidence"):
            engine.plan_collection(request)
