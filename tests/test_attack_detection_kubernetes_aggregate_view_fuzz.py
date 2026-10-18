"""Bounded JSON shape mutations for the aggregate-to-view detector."""
from __future__ import annotations

import copy
import importlib.util
import random
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("candidate_cases", HERE / "test_attack_detection_kubernetes_aggregate_view_next.py")
assert spec and spec.loader
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)


VALUES = (None, False, True, 0, -1, 1.5, "", "x", "{malformed-json", "http://[",
          [], [None, {}], {}, {"unexpected": [None]}, "\ud800")
DIRECT_PATHS = (
    ("apiVersion",), ("kind",), ("stage",), ("verb",), ("auditID",),
    ("stageTimestamp",), ("cluster_id",), ("requestURI",),
    ("objectRef",), ("objectRef", "apiGroup"), ("objectRef", "resource"),
    ("objectRef", "namespace"), ("objectRef", "subresource"),
    ("responseStatus",), ("responseStatus", "code"), ("responseStatus", "status"),
    ("user",), ("user", "username"), ("responseObject",),
    ("responseObject", "apiVersion"), ("responseObject", "kind"),
    ("responseObject", "metadata"), ("responseObject", "metadata", "name"),
    ("responseObject", "metadata", "uid"), ("responseObject", "metadata", "labels"),
    ("responseObject", "metadata", "labels", "rbac.authorization.k8s.io/aggregate-to-view"),
    ("responseObject", "rules"), ("responseObject", "rules", 0),
    ("responseObject", "rules", 0, "apiGroups"),
    ("responseObject", "rules", 0, "resources"),
    ("responseObject", "rules", 0, "verbs"),
)
GKE_PATHS = (
    ("logName",), ("resource",), ("resource", "type"), ("resource", "labels"),
    ("resource", "labels", "project_id"), ("resource", "labels", "location"),
    ("resource", "labels", "cluster_name"), ("labels",), ("insertId",),
    ("timestamp",), ("protoPayload",), ("protoPayload", "@type"),
    ("protoPayload", "serviceName"), ("protoPayload", "methodName"),
    ("protoPayload", "status"), ("protoPayload", "status", "code"),
    ("protoPayload", "authenticationInfo"),
    ("protoPayload", "authenticationInfo", "principalEmail"),
    ("protoPayload", "request"), ("protoPayload", "request", "metadata"),
    ("protoPayload", "request", "metadata", "name"),
    ("protoPayload", "response"), ("protoPayload", "response", "apiVersion"),
    ("protoPayload", "response", "kind"),
    ("protoPayload", "response", "metadata"),
    ("protoPayload", "response", "metadata", "name"),
    ("protoPayload", "response", "metadata", "labels"),
    ("protoPayload", "response", "rules"),
    ("protoPayload", "response", "rules", 0),
    ("protoPayload", "response", "rules", 0, "apiGroups"),
    ("protoPayload", "response", "rules", 0, "resources"),
    ("protoPayload", "response", "rules", 0, "verbs"),
)


def _replace(value, path, replacement):
    cursor = value
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = replacement


@pytest.mark.parametrize("factory,paths", [(cases.native, DIRECT_PATHS), (cases.gke, GKE_PATHS)])
def test_bounded_malformed_json_shapes_never_raise_and_do_not_poison_next_event(factory, paths):
    # Every high-value nested field is replaced by every JSON-like wrong type,
    # followed by a fresh valid event. A deterministic 300 multi-field sample
    # catches interactions while keeping CI work and memory bounded.
    normal = factory()
    assert cases.normalize(normal)
    for path in paths:
        for replacement in VALUES:
            damaged = copy.deepcopy(normal)
            _replace(damaged, path, replacement)
            cases.normalize(damaged)
            assert cases.normalize(factory()) is not None
    rng = random.Random(20261018)
    for _ in range(300):
        damaged = copy.deepcopy(normal)
        for path in rng.sample(paths, rng.randint(1, 4)):
            try:
                _replace(damaged, path, rng.choice(VALUES))
            except (KeyError, IndexError, TypeError):
                # An earlier replacement of the parent path made this child
                # unavailable. That parent shape has already been exercised.
                pass
        cases.normalize(damaged)
        assert cases.normalize(factory()) is not None


@pytest.mark.parametrize("factory", [cases.native, cases.gke])
def test_non_mapping_top_level_values_are_ignored(factory):
    for invalid in VALUES:
        assert cases.normalize(invalid) is None
        assert cases.normalize(factory()) is not None
