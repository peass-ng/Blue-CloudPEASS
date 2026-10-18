"""Coverage paging behavior for legacy reports without count sidecars."""
import copy
from collections import Counter
from concurrent.futures import CancelledError, ThreadPoolExecutor
from threading import Event, Lock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.auth.api_keys import mint_key
from peaso.server.config import Settings
from peaso.storage import StoreError
from peaso.server.app import create_app


SCAN = "1" * 32


class Users:
    def authenticate(self, header):
        if header in {"Bearer alice", "Bearer bob"}:
            return Identity(header.split()[1])
        raise HTTPException(401, "Invalid authentication")


class Store:
    def __init__(self):
        self.reports = {("alice", SCAN): "manifest-a", ("bob", SCAN): "manifest-b"}
        self.keys = {}

    def job(self, tenant, ident):
        reference = self.reports.get((tenant, ident))
        if reference is None:
            raise StoreError(404, "Scan not found")
        return {"id": ident, "status": "completed", "report": reference}

    def api_key(self, key_id):
        return self.keys.get(key_id)

    def touch_api_key(self, tenant, key_id):
        return self.keys.get(key_id, {}).get("tenant") == tenant


class Artifacts:
    def __init__(self):
        self.values = {}
        self.reads = Counter()
        self.fail = set()

    def get(self, tenant, reference):
        self.reads[(tenant, reference)] += 1
        if (tenant, reference) in self.fail:
            raise RuntimeError("fake artifact read failed")
        return copy.deepcopy(self.values[(tenant, reference)])


def seed(artifacts, tenant, manifest_ref, prefix, sizes, extra=False):
    refs, rows = [], []
    for chunk, size in enumerate(sizes):
        ref = f"{prefix}-{chunk}"
        refs.append(ref)
        group = [{"id": len(rows) + index, "status": "evaluated", "padding": "x" * 128}
                 for index in range(size)]
        rows.extend(group)
        artifacts.values[(tenant, ref)] = {"items": group}
    summary = {"snapshot_id": prefix}
    if extra:
        summary["snapshot_metadata"] = {"scan_coverage": [{
            "level": "credential_target", "status": "not_collected",
            "error_code": "duplicate_account_target", "account": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/reader"}]}
    artifacts.values[(tenant, manifest_ref)] = {
        "bundle_version": 1, "summary": summary, "coverage_chunks": refs,
        "coverage_count": len(rows),
    }
    return refs, rows


@pytest.fixture
def api(tmp_path):
    store, artifacts = Store(), Artifacts()
    refs, rows = seed(artifacts, "alice", "manifest-a", "shared", [250] * 93 + [31], extra=True)
    # Identical reference strings in another tenant must still be isolated.
    seed(artifacts, "bob", "manifest-b", "shared", [1] * 94)
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    app = create_app(settings, store=store, authenticator=Users(), artifacts=artifacts)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        yield client, app, store, artifacts, refs, rows


def get(client, offset, limit=100, tenant="alice"):
    return client.get(f"/api/scans/{SCAN}/coverage", params={"offset": offset, "limit": limit},
                      headers={"Authorization": f"Bearer {tenant}"})


def assert_page(response, rows, offset, limit, extra=False):
    assert response.status_code == 200, response.text
    total = len(rows) + int(extra)
    expected = rows[offset:offset + limit]
    if extra and offset <= len(rows) < offset + limit:
        expected += [{"level": "credential_target", "scope": "123456789012",
                      "account": "123456789012", "role_arn": "arn:aws:iam::123456789012:role/reader",
                      "status": "not_collected", "code": "duplicate_account_target",
                      "error_code": "duplicate_account_target"}]
    body = response.json()
    assert body == {"items": expected, "offset": offset, "limit": limit, "total": total,
                    "has_more": offset + len(expected) < total,
                    "next_offset": offset + len(expected) if offset + len(expected) < total else None}


def test_cold_and_warm_94_chunks_arbitrary_pages_and_last_row(api):
    client, app, _, artifacts, refs, rows = api
    assert_page(get(client, 333, 75), rows, 333, 75, extra=True)
    assert [artifacts.reads[("alice", ref)] for ref in refs] == [1] * 94
    artifacts.reads.clear()
    for offset, limit in [(0, 1), (248, 7), (999, 500), (len(rows)-1, 2),
                          (len(rows), 1), (len(rows)+1, 10)]:
        assert_page(get(client, offset, limit), rows, offset, limit, extra=True)
    # Only chunks intersecting requested report rows were read after warming.
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 7
    assert len(app.state.legacy_coverage_count_index) == 1
    key, sizes = next(iter(app.state.legacy_coverage_count_index.items()))
    assert key == ("alice", "manifest-a", tuple(refs))
    assert sizes == (250,) * 93 + (31,)
    assert all(type(size) is int for size in sizes)


def test_tenant_and_manifest_keys_and_lru_bound(api):
    client, app, store, artifacts, refs, rows = api
    assert_page(get(client, 0, 1), rows, 0, 1, extra=True)
    assert get(client, 0, 1, tenant="bob").json()["total"] == 94
    assert sum(artifacts.reads[("bob", ref)] for ref in refs) == 94
    artifacts.values[("alice", "manifest-same-refs")] = copy.deepcopy(
        artifacts.values[("alice", "manifest-a")])
    store.reports[("alice", SCAN)] = "manifest-same-refs"
    artifacts.reads.clear()
    assert_page(get(client, 0, 1), rows, 0, 1, extra=True)
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 94
    for number in range(4):
        manifest = f"manifest-new-{number}"
        new_refs, new_rows = seed(artifacts, "alice", manifest, f"new-{number}", [number + 2])
        store.reports[("alice", SCAN)] = manifest
        assert_page(get(client, 0, 1), new_rows, 0, 1)
        assert artifacts.reads[("alice", new_refs[0])] == 1
    assert len(app.state.legacy_coverage_count_index) == 4
    assert all(not any(isinstance(part, dict) for part in key) for key in app.state.legacy_coverage_count_index)


def test_valid_sidecar_still_uses_existing_fast_path(api):
    client, app, _, artifacts, refs, rows = api
    artifacts.values[("alice", "manifest-a")]["coverage_chunk_counts"] = [250] * 93 + [31]
    assert_page(get(client, 500, 20), rows, 500, 20, extra=True)
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 1
    assert not app.state.legacy_coverage_count_index
    artifacts.values[("alice", refs[2])]["items"].pop()
    assert get(client, 500, 20).status_code == 409


def test_failed_cold_read_never_caches_partial_or_zero(api):
    client, app, _, artifacts, refs, rows = api
    artifacts.fail.add(("alice", refs[17]))
    assert get(client, 0, 1).status_code == 500
    assert not app.state.legacy_coverage_count_index
    artifacts.fail.clear()
    assert_page(get(client, 0, 1), rows, 0, 1, extra=True)
    assert artifacts.reads[("alice", refs[0])] == 2


def test_warm_chunk_mismatch_409_and_sidecar_fallback(api):
    client, app, _, artifacts, refs, rows = api
    assert_page(get(client, 250, 1), rows, 250, 1, extra=True)
    artifacts.values[("alice", refs[1])]["items"].pop()
    assert get(client, 250, 1).status_code == 409
    artifacts.values[("alice", refs[1])]["items"].append(rows[499])
    manifest = artifacts.values[("alice", "manifest-a")]
    for malformed in (None, [250], [True] + [250] * 92 + [31],
                      [-1] + [250] * 92 + [31]):
        manifest["coverage_chunk_counts"] = malformed
        artifacts.reads.clear()
        assert_page(get(client, 250, 1), rows, 250, 1, extra=True)
        assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 94
    assert len(app.state.legacy_coverage_count_index) == 1


def test_inline_coverage_ignores_index(api):
    client, app, _, artifacts, refs, _ = api
    artifacts.values[("alice", "manifest-a")] = {
        "bundle_version": 0, "coverage": [{"id": "inline"}],
        "coverage_chunks": refs, "coverage_chunk_counts": [250] * 94,
    }
    assert get(client, 0, 1).json()["items"] == [{"id": "inline"}]
    assert not app.state.legacy_coverage_count_index
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 0


def test_owner_and_query_validation_before_index(api):
    client, app, store, artifacts, refs, rows = api
    assert get(client, 0, 1, tenant="bob").status_code == 200
    assert client.get(f"/api/scans/{SCAN}/coverage", params={"offset": -1},
                      headers={"Authorization": "Bearer alice"}).status_code == 422
    assert client.get(f"/api/scans/{'2' * 32}/coverage",
                      headers={"Authorization": "Bearer alice"}).status_code == 404
    assert client.get(f"/api/scans/{SCAN}/coverage",
                      headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert all(key[0] == "bob" for key in app.state.legacy_coverage_count_index)
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 0
    key_id, token, digest = mint_key()
    store.keys[key_id] = {"tenant": "alice", "secret_sha256": digest,
                          "revoked_at": None, "expires_at": None}
    response = client.get(f"/api/scans/{SCAN}/coverage", params={"offset": 300, "limit": 1},
                          headers={"Authorization": f"Bearer {token}"})
    assert_page(response, rows, 300, 1, extra=True)
    assert all(token not in repr(key) for key in app.state.legacy_coverage_count_index)
    store.keys[key_id]["revoked_at"] = 1
    assert client.get(f"/api/scans/{SCAN}/coverage",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_exact_pages_and_extra_target(api):
    client, app, _, _, _, rows = api
    for offset, limit in ((0, 1), (249, 2), (333, 75), (23280, 2), (23281, 1), (23282, 1)):
        assert_page(get(client, offset, limit), rows, offset, limit, extra=True)
    assert len(app.state.legacy_coverage_count_index) == 1


def test_reference_bound_and_full_scan_fallback(api):
    client, app, store, artifacts, _, _ = api
    refs, rows = seed(artifacts, "alice", "manifest-1024", "bounded", [1] * 1024)
    store.reports[("alice", SCAN)] = "manifest-1024"
    assert_page(get(client, 512, 2), rows, 512, 2)
    assert len(app.state.legacy_coverage_count_index) == 1
    key, sizes = next(iter(app.state.legacy_coverage_count_index.items()))
    assert key == ("alice", "manifest-1024", tuple(refs))
    assert sizes == (1,) * 1024
    artifacts.reads.clear()
    assert_page(get(client, 512, 2), rows, 512, 2)
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 2
    refs, rows = seed(artifacts, "alice", "manifest-1025", "fallback", [1] * 1025)
    store.reports[("alice", SCAN)] = "manifest-1025"
    assert_page(get(client, 512, 2), rows, 512, 2)
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 1025
    assert len(app.state.legacy_coverage_count_index) == 1
    assert ("alice", "manifest-1025", tuple(refs)) not in app.state.legacy_coverage_count_index


def test_simultaneous_cold_requests_singleflight(api):
    client, app, _, artifacts, refs, rows = api
    entered, waiting, release = Event(), Event(), Event()
    gate = Lock()
    first_chunk = True
    original_get = artifacts.get

    def blocked_get(tenant, reference):
        nonlocal first_chunk
        if tenant == "alice" and reference == refs[0]:
            with gate:
                block = first_chunk
                first_chunk = False
            if block:
                entered.set()
                assert release.wait(5), "cold-read gate timed out"
        return original_get(tenant, reference)

    artifacts.get = blocked_get
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(get, client, 0, 1)
            assert entered.wait(5)
            assert len(app.state.legacy_coverage_count_inflight) == 1
            flight = next(iter(app.state.legacy_coverage_count_inflight.values()))
            original_result = flight.result

            def observed_result(*args, **kwargs):
                waiting.set()
                return original_result(*args, **kwargs)

            flight.result = observed_result
            second = pool.submit(get, client, 250, 2)
            assert waiting.wait(5)
            release.set()
            assert_page(first.result(timeout=5), rows, 0, 1, extra=True)
            assert_page(second.result(timeout=5), rows, 250, 2, extra=True)
    finally:
        release.set()
        artifacts.get = original_get
    assert sum(artifacts.reads[("alice", ref)] for ref in refs) == 95
    assert not app.state.legacy_coverage_count_inflight
    assert len(app.state.legacy_coverage_count_index) == 1


@pytest.mark.parametrize("wait_error", [TimeoutError, CancelledError])
def test_follower_recovers_from_stalled_or_cancelled_flight(api, wait_error):
    client, app, _, artifacts, refs, rows = api
    entered, release = Event(), Event()
    original_get = artifacts.get
    first_chunk = True
    gate = Lock()

    def blocked_get(tenant, reference):
        nonlocal first_chunk
        if tenant == "alice" and reference == refs[0]:
            with gate:
                block = first_chunk
                first_chunk = False
            if block:
                entered.set()
                assert release.wait(5), "leader gate timed out"
        return original_get(tenant, reference)

    artifacts.get = blocked_get
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(get, client, 0, 1)
            assert entered.wait(5)
            flight = next(iter(app.state.legacy_coverage_count_inflight.values()))

            def interrupted_result(timeout):
                assert timeout == 5
                raise wait_error()

            flight.result = interrupted_result
            second = pool.submit(get, client, 250, 2)
            assert_page(second.result(timeout=5), rows, 250, 2, extra=True)
            release.set()
            assert_page(first.result(timeout=5), rows, 0, 1, extra=True)
    finally:
        release.set()
        artifacts.get = original_get
    assert not app.state.legacy_coverage_count_inflight
    assert len(app.state.legacy_coverage_count_index) == 1
