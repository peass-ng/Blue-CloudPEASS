"""Scoped component prework memo parity and bounded repeated evaluation."""

import copy
import json
import statistics
import time
import tracemalloc
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks import k8s_ports_components as ports
from peaso.checks.facts import MemoIndex, Unavailable
from peaso.checks.fixtures import CASES
from peaso.snapshot import freeze


REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


def bytes_of(outcome):
    return json.dumps(outcome, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def test_every_component_fixture_has_registry_status_and_evidence_parity():
    cases = (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"),
             ("malformed", "UNKNOWN"), ("denied", "UNKNOWN"))
    for check_id in ports.IDS:
        check = REGISTRY[check_id]
        for case, expected in cases:
            item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[check_id][case])
            if case == "pass" and check_id.endswith(".container_argument_kubelet_authorization_mode_no_always_allow"):
                # Explicit current-only native fixture; do not rewrite CASES.
                _, rows = ports.pod_spec(item, check.kind)
                assert rows[0]["_component_config"]["flags"]["authorization-mode"] == "RBAC"
                rows[0]["_component_config"]["flags"]["authorization-mode"] = "Webhook"
            item = freeze(item)
            original = bytes_of(item)
            plain = check.evaluate(item, {})
            index = MemoIndex()
            first = check.evaluate(item, index)
            second = check.evaluate(item, index)
            assert first[0] == expected, (check_id, case, first)
            assert bytes_of(plain) == bytes_of(first) == bytes_of(second), (check_id, case)
            assert bytes_of(item) == original, (check_id, case)


@pytest.mark.parametrize("item, stage", [
    ({"spec": {"containers": []}}, "pod_spec"),
    ({"metadata": {"labels": []}, "spec": {"containers": [{"name": "api"}]}}, "component_hints"),
])
def test_repeated_unavailable_replays_original_error_and_retains_item(monkeypatch, item, stage):
    item = freeze(item)
    spec = ports.SPECS["container_argument_api_server_anonymous_auth_disabled"]
    original = ports.pod_spec if stage == "pod_spec" else ports.component_hints
    calls = 0

    def counted(*args):
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(ports, stage, counted)
    with pytest.raises(Unavailable) as baseline:
        ports.evaluate_component(item, "pod", spec, {})
    assert calls == 1
    index = MemoIndex()
    for _ in range(3):
        with pytest.raises(Unavailable) as cached:
            ports.evaluate_component(item, "pod", spec, index)
        assert (type(cached.value), cached.value.args) == (type(baseline.value), baseline.value.args)
    assert calls == 2
    entries = [value for key, value in index.memo.items() if key[0] == "k8s_component_prework"]
    assert any(value[1][0] is item for value in entries)  # Strong identity on failed and successful reads.


def test_original_spec_unpacking_precedes_component_hints_error(monkeypatch):
    item = freeze({"metadata": {"labels": []}, "spec": {"containers": [{"name": "api"}]}})
    index = MemoIndex()
    with pytest.raises(ValueError, match="not enough values to unpack"):
        ports.evaluate_component(item, "pod", (), index)
    assert len(index.memo) == 1  # PodSpec was read, but hints were not.


@pytest.mark.parametrize("variant, check_id, expected", [
    ("incomplete", "k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled", "UNKNOWN"),
    ("denied_config", "k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled", "UNKNOWN"),
    ("malformed_hints", "k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled", "UNKNOWN"),
    ("removed_version", "k8s.ports.pod.container_argument_pod_security_policy_enabled", "NOT_APPLICABLE"),
    ("missing_version", "k8s.ports.pod.container_argument_pod_security_policy_enabled", "UNKNOWN"),
])
def test_incomplete_denied_malformed_and_version_outcomes_match(variant, check_id, expected):
    item = copy.deepcopy(CASES[check_id]["pass"])
    config = item["spec"]["containers"][0]["_component_config"]
    if variant == "incomplete":
        config["flags_complete"] = False
    elif variant == "denied_config":
        config["collection_status"] = "denied"
    elif variant == "malformed_hints":
        item["metadata"] = {"labels": []}
    elif variant == "removed_version":
        config["version"] = "v1.25.0"
    else:
        config.pop("version")
    item = freeze(item)
    check = REGISTRY[check_id]
    plain = check.evaluate(item, {})
    index = MemoIndex()
    first = check.evaluate(item, index)
    second = check.evaluate(item, index)
    assert plain[0] == expected
    assert bytes_of(plain) == bytes_of(first) == bytes_of(second)


def test_prework_once_per_item_and_scope_without_cross_index_leakage(monkeypatch):
    item = freeze(copy.deepcopy(CASES["k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled"]["pass"]))
    other = freeze(copy.deepcopy(item))
    checks = [REGISTRY[cid] for cid in ports.IDS if REGISTRY[cid].kind == "pod"][:8]
    counts = {"pod_spec": 0, "component_hints": 0}
    original_spec, original_hints = ports.pod_spec, ports.component_hints

    def counted_spec(*args):
        counts["pod_spec"] += 1
        return original_spec(*args)

    def counted_hints(*args):
        counts["component_hints"] += 1
        return original_hints(*args)

    monkeypatch.setattr(ports, "pod_spec", counted_spec)
    monkeypatch.setattr(ports, "component_hints", counted_hints)
    first = MemoIndex()
    for check in checks:
        assert bytes_of(check.evaluate(item, first)) == bytes_of(check.evaluate(item, {}))
    assert counts == {"pod_spec": len(checks) + 1, "component_hints": len(checks) + 1}
    assert len(first.memo) == 2
    second = MemoIndex()
    checks[0].evaluate(item, second)
    checks[0].evaluate(other, first)
    assert counts == {"pod_spec": len(checks) + 3, "component_hints": len(checks) + 3}
    assert len(second.memo) == 2 and len(first.memo) == 4


def test_repeated_component_benchmark_is_bounded_and_measurably_faster():
    cid = "k8s.ports.pod.container_argument_api_server_anonymous_auth_disabled"
    item = freeze(copy.deepcopy(CASES[cid]["pass"]))
    spec = ports.SPECS["container_argument_api_server_anonymous_auth_disabled"]
    outcomes = []
    times = {"plain": [], "memo": []}
    for _ in range(3):
        for mode in ("plain", "memo"):
            index = {} if mode == "plain" else MemoIndex()
            started = time.perf_counter()
            for _ in range(3000):
                outcome = ports.evaluate_component(item, "pod", spec, index)
            times[mode].append(time.perf_counter() - started)
            outcomes.append(bytes_of(outcome))
            if mode == "memo":
                assert len(index.memo) == 2
    assert len(set(outcomes)) == 1
    plain, memo = statistics.median(times["plain"]), statistics.median(times["memo"])
    tracemalloc.start()
    try:
        index = MemoIndex()
        for _ in range(3000):
            ports.evaluate_component(item, "pod", spec, index)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    print(f"component memo benchmark plain={plain:.6f}s memo={memo:.6f}s peak={peak}B entries={len(index.memo)}")
    artifact = Path(".cache/cspm-k8s-component-memoization/benchmark.json")
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps({"plain_median_seconds": plain, "memo_median_seconds": memo,
        "speedup": plain / memo, "memo_peak_bytes": peak, "memo_entries": len(index.memo),
        "iterations_per_round": 3000, "rounds": 3}, indent=2) + "\n")
    assert memo < plain and memo < 3.0
    assert peak < 2_000_000 and len(index.memo) == 2
