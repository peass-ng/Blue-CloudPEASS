"""Known workload violations take priority over unavailable unrelated containers."""
import copy
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


def status(cid, containers, kind="pod"):
    spec = {"containers": copy.deepcopy(containers)}
    item = {"metadata": {"name": "workload", "namespace": "apps"}}
    item["spec"] = spec if kind == "pod" else {"template": {"spec": spec}}
    snapshot = make_snapshot("k8s", ["*"], [
        {"type": kind, "scope": "*", "status": "collected", "items": [item]}],
        created_at="2026-10-17T00:00:00Z")
    findings = [row for row in evaluate_snapshot(snapshot, checks=[cid])["findings"]
                if row["check_id"] == cid]
    assert len(findings) == 1
    return findings[0]["status"]


CASES = (
    ("privileged", {"securityContext": {"privileged": False}},
     {"securityContext": {"privileged": True}},
     {"securityContext": {"privileged": False, "_coverage": {"privileged": {"status": "denied"}}}}),
    ("container_runtime_default_seccomp", {"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}},
     {"securityContext": {"seccompProfile": {"type": "Unconfined"}}},
     {"securityContext": {"seccompProfile": {"type": "NewType"}}}),
    ("context_present", {"securityContext": {}}, {},
     {"securityContext": {}, "_coverage": {"securityContext": {"status": "denied"}}}),
    ("no_added_capabilities", {"securityContext": {"capabilities": {"add": []}}},
     {"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}},
     {"securityContext": {"capabilities": {"add": [], "_coverage": {"add": {"status": "denied"}}}}}),
    ("cpu_limit", {"resources": {"limits": {"cpu": "1"}}},
     {"resources": {"limits": {}}},
     {"resources": {"limits": {"cpu": "1"}, "_coverage": {"limits": {"status": "denied"}}}}),
    ("readiness_probe", {"readinessProbe": {"tcpSocket": {"port": 8080}}},
     {}, {"_coverage": {"readinessProbe": {"status": "denied"}}}),
    ("pinned_image", {"image": "app:v2"}, {"image": "app:latest"},
     {"image": "app:v2", "_coverage": {"image": {"status": "denied"}}}),
    ("content_digest_or_always_pull",
     {"image": "app@sha256:" + "a" * 64, "imagePullPolicy": "IfNotPresent"},
     {"image": "app:v2", "imagePullPolicy": "IfNotPresent"},
     {"image": "app@sha256:malformed", "imagePullPolicy": "IfNotPresent"}),
    ("always_pull", {"image": "app:v2", "imagePullPolicy": "Always"},
     {"image": "app:v2", "imagePullPolicy": "IfNotPresent"},
     {"image": "app:v2", "imagePullPolicy": "FuturePolicy"}),
)


def containers(*values):
    return [{"name": "item-" + str(i), **copy.deepcopy(value)} for i, value in enumerate(values)]


@pytest.mark.parametrize("predicate,good,bad,unreadable", CASES, ids=[x[0] for x in CASES])
@pytest.mark.parametrize("bad_first", [True, False], ids=["bad-first", "bad-last"])
def test_known_violation_survives_unavailable_peer(predicate, good, bad, unreadable, bad_first):
    kind = ("deployment" if predicate == "container_runtime_default_seccomp" else
            "replicationcontroller" if predicate == "privileged" else "pod")
    cid = "k8s.ports." + kind + "." + predicate
    rows = containers(bad, unreadable) if bad_first else containers(unreadable, bad)
    assert status(cid, rows, kind) == "FAIL"


@pytest.mark.parametrize("predicate,good,bad,unreadable", CASES, ids=[x[0] for x in CASES])
def test_full_authority_still_required_for_positive(predicate, good, bad, unreadable):
    kind = ("deployment" if predicate == "container_runtime_default_seccomp" else
            "replicationcontroller" if predicate == "privileged" else "pod")
    cid = "k8s.ports." + kind + "." + predicate
    assert status(cid, containers(good), kind) == "PASS"
    assert status(cid, containers(bad), kind) == "FAIL"
    assert status(cid, containers(good, unreadable), kind) == "UNKNOWN"
