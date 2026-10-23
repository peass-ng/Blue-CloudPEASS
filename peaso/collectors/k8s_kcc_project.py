"""Minimal Config Connector Project identity needed for policy references."""


def project_identity(row):
    spec = row.get("spec") or {}
    status = row.get("status") or {}
    metadata = row.get("metadata") or {}
    if not all(isinstance(value, dict) for value in (spec, status, metadata)):
        raise ValueError("malformed Config Connector Project")
    conditions = status.get("conditions") or []
    if not isinstance(conditions, list):
        raise ValueError("malformed Config Connector Project conditions")
    return {
        "apiVersion": row.get("apiVersion"),
        "kind": row.get("kind"),
        "metadata": {key: metadata.get(key) for key in
                     ("name", "namespace", "uid", "resourceVersion", "generation")},
        "spec": {"resourceID": spec.get("resourceID")},
        "status": {"number": status.get("number"),
                   "observedGeneration": status.get("observedGeneration"),
                   "conditions": [{"type": condition.get("type"),
                                   "status": condition.get("status")}
                                  for condition in conditions
                                  if isinstance(condition, dict) and condition.get("type") == "Ready"]},
    }
