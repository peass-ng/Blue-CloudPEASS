"""Aggregating ClusterRoles must select a label set a new role can carry."""

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import C, crb, crole, k8s_snap, user


def test_aggregation_selector_cannot_be_contradictory():
    technique = "k8s-rbac-escalate-aggregating-clusterrole"
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == technique)
    aggregated = crole("aggregated", [])
    editor = crole("editor", [{"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["clusterroles"], "verbs": ["create", "escalate"]}])
    binds = [crb("agg-bind", "aggregated", user("dev")), crb("editor-bind", "editor", user("dev"))]

    def path(selectors):
        aggregated["aggregationRule"] = {"clusterRoleSelectors": selectors}
        return reached(privesc.analyze(k8s_snap(clusterroles=[aggregated, editor], crbs=binds),
                                       entries=[entry]), f"k8s:{C}:user:dev", technique)

    assert path([{"matchLabels": {"aggregate-to-view": "true"}}])
    assert path([{"matchExpressions": [{"key": "aggregate-to-view", "operator": "In", "values": ["true"]}]}])
    assert path([{"matchLabels": {"aggregate-to-view": "true"}, "matchExpressions": [
        {"key": "aggregate-to-view", "operator": "DoesNotExist"}]}]) == {}
    assert path([{"matchExpressions": [{"key": "aggregate-to-view", "operator": "In", "values": ["true"]},
                                       {"key": "aggregate-to-view", "operator": "NotIn", "values": ["true"]}]}]) == {}


def test_aggregation_escalate_name_must_allow_creating_a_new_role():
    technique = "k8s-rbac-escalate-aggregating-clusterrole"
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == technique)
    aggregated = crole("aggregated", [], aggregation={"aggregate-to-view": "true"})
    editor = crole("editor", [{"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["clusterroles"], "verbs": ["create"]},
                              {"apiGroups": ["rbac.authorization.k8s.io"],
                               "resources": ["clusterroles"], "verbs": ["escalate"],
                               "resourceNames": ["editor"]}])
    binds = [crb("agg-bind", "aggregated", user("dev")), crb("editor-bind", "editor", user("dev"))]

    def path():
        return reached(privesc.analyze(k8s_snap(clusterroles=[aggregated, editor], crbs=binds),
                                       entries=[entry]), f"k8s:{C}:user:dev", technique)

    assert path() == {}  # the sole escalate name already exists
    editor["rules"][1]["resourceNames"] = ["new-role"]
    assert path()
