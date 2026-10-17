"""Bound the native operation read before any real request or source selection."""
from copy import deepcopy
import pytest
from peaso.collectors import azure_wave_compute_native as native
from tests.test_peaso_azure_wave_compute_native_collector import Reader, SCOPE, VM, _vm, _result, _policy


def test_query_contains_only_the_native_latest_operation_identity():
    reader = Reader([_result()])
    native.collect(reader, None, [SCOPE], {native.KIND}, _policy())
    query = reader.calls[0][1]["query"]
    assert '| where id in~ (' in query
    assert VM + "/patchInstallationResults/operation-1" in query


def test_duplicate_result_ids_are_rejected_before_projection():
    reader = Reader([_result(), _result()])
    with pytest.raises(ValueError, match="duplicate Update Manager"):
        native.collect(reader, None, [SCOPE], {native.KIND}, _policy())


def test_duplicate_vm_without_an_operation_cannot_hide_before_selection():
    reader = Reader([])
    duplicate = deepcopy(_vm())
    duplicate["instanceView"]["patchStatus"]["lastPatchInstallationSummary"] = {}
    reader.collections[0]["items"] = [duplicate, _vm()]
    with pytest.raises(ValueError, match="duplicate patch result VM"):
        native.collect(reader, None, [SCOPE], {native.KIND}, _policy())
    assert not reader.calls


def test_excessive_operation_set_stops_before_arg_request():
    reader = Reader([])
    reader.collections[0]["items"] = []
    for number in range(native.MAX_OPERATIONS + 1):
        row = _vm()
        row["id"] = VM + str(number)
        reader.collections[0]["items"].append(row)
    with pytest.raises(ValueError, match="operation limit"):
        native.collect(reader, None, [SCOPE], {native.KIND}, _policy())
    assert not reader.calls


def test_hard_request_ceiling_prevents_ninth_page_network_call():
    calls = []
    class PaginatedReader(Reader):
        def pages(self, request, url, **kwargs):
            for _ in range(native.MAX_PAGES + 1):
                request(url, kwargs["body"])
                yield []
    reader = PaginatedReader([])
    with pytest.raises(ValueError, match="hard request/page limit"):
        native.collect(reader, lambda *args: calls.append(args), [SCOPE], {native.KIND}, _policy())
    assert len(calls) == native.MAX_PAGES
