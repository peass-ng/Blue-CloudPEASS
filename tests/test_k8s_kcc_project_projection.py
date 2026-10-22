"""Named Config Connector Project references retain identity without unrelated fields."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def projection():
    path = Path(__file__).resolve().parents[1] / "peaso/collectors/k8s_kcc_project.py"
    spec = spec_from_file_location("k8s_kcc_project_projection", path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.project_identity


def test_project_identity_keeps_only_reference_and_readiness_facts():
    row = {"apiVersion": "resourcemanager.cnrm.cloud.google.com/v1beta1",
           "kind": "Project", "metadata": {"name": "managed-project", "namespace": "team-a",
                                          "generation": 1, "annotations": {"token": "secret"}},
           "spec": {"resourceID": "demo-project1",
                    "billingAccountRef": {"external": "billingAccounts/secret"}},
           "status": {"number": "123", "observedGeneration": 1,
                      "conditions": [{"type": "Ready", "status": "True", "message": "secret"}]}}
    result = projection()(row)
    assert result["spec"] == {"resourceID": "demo-project1"}
    assert result["status"]["conditions"] == [{"type": "Ready", "status": "True"}]
    assert "secret" not in repr(result)
