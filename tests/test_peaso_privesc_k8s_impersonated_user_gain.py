"""A traditional user impersonation must add an RBAC permission."""

from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import crb, crole, k8s_snap, user


TECHNIQUE = "k8s-rbac-impersonate-users"
ENTRY = next(item for item in privesc.catalog()["entries"] if item["id"] == TECHNIQUE)
SOURCE = "k8s:c1:user:dev"
TARGET = "k8s:c1:user:alice"
SECRET_READ = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}


def run(target_rules, *, source_has_right=False, complete=True, broad=False):
    impersonate = {"apiGroups": [""], "resources": ["users"],
                   "verbs": ["impersonate"]}
    if not broad:
        impersonate["resourceNames"] = ["alice"]
    writer = crole("writer", [impersonate] + ([SECRET_READ] if source_has_right else []))
    target = crole("target", target_rules)
    snapshot = k8s_snap(clusterroles=[writer, target],
                        crbs=[crb("writer-binding", "writer", user("dev")),
                              crb("target-binding", "target", user("alice"))])
    if not complete:
        next(c for c in snapshot["collections"] if c["type"] == "rolebinding")["status"] = "partial"
    result = privesc.analyze(snapshot, entries=[ENTRY], include_unknown=True)
    return reached(result, SOURCE, TECHNIQUE)


def test_impersonating_user_with_no_new_right_is_not_escalation():
    assert run([]) == {}
    assert run([], broad=True) == {}
    assert run([SECRET_READ], source_has_right=True) == {}


def test_impersonating_user_with_new_right_remains_visible():
    assert run([SECRET_READ])[TARGET] in ("derived", "conditional")
    assert run([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])[TARGET] in (
        "derived", "conditional")


def test_incomplete_target_rbac_does_not_claim_a_definite_gain():
    got = run([], complete=False)
    assert TARGET not in got
    assert set(got.values()) <= {"unknown"}
