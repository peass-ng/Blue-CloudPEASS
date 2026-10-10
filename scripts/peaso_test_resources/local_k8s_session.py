"""Create an inert localhost-only kind cluster; remove exact owned cluster finally."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid


def run(command, *, json_output=False):
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
    return json.loads(result.stdout) if json_output else result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    directory = Path(args.directory).resolve()
    name = "peaso-test-" + uuid.uuid4().hex[:12]
    kind = str(directory / "kind")
    kubeconfig = directory / (name + ".kubeconfig")
    config = directory / (name + ".kind.yaml")
    ledger = directory / "local-k8s-ledger.json"
    owner = uuid.uuid4().hex
    daemon = run(["docker", "info", "--format", "{{.ID}}"])
    network_name = name + "-network"
    data = json.loads(ledger.read_text()) if ledger.exists() else {"schema_version": 1, "task_id": "task_02a312b5ac1f", "dispatch_id": "ctx_e2284cf3ad99", "resources": []}
    if data["task_id"] != "task_02a312b5ac1f":
        raise RuntimeError("Wrong ledger owner")
    data["resources"].append({
        "provider": "local-k8s", "account": None, "project": None, "subscription": None, "region": "local-docker",
        "name": name, "id": name, "creation_status": "planned", "delete_operation": "kind delete cluster --name exact --kubeconfig private",
        "verification": "pending", "owner_token": owner, "docker_id": daemon,
        "cleanup_deadline": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        "workload_resources": [], "docker_network": {"name": network_name, "id": None, "creation_status": "planned", "owner_token": owner}})
    row = data["resources"][-1]
    def save():
        ledger.write_text(json.dumps(data, indent=2) + "\n")
        os.chmod(ledger, 0o600)
    save()  # Before the first cluster/container creation.
    config.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  apiServerAddress: 127.0.0.1\nnodes:\n- role: control-plane\n")
    os.chmod(config, 0o600)
    def identity():
        if run(["docker", "info", "--format", "{{.ID}}"] ) != daemon:
            raise RuntimeError("Docker daemon identity mismatch")
    def owned_container():
        ids = run(["docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster=" + name]).split()
        for ident in ids:
            item = run(["docker", "inspect", ident], json_output=True)[0]
            if item["Config"]["Labels"].get("io.x-k8s.kind.cluster") != name or item["Name"] != "/" + name + "-control-plane":
                raise RuntimeError("Unexpected cluster container")
        return ids
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        identity()
        if owned_container():
            raise RuntimeError("Cluster name already exists")
        identity()
        network_id = run(["docker", "network", "create", "--label", "peaso-test-owner=" + owner, "--label", "peaso-test-task=task_02a312b5ac1f", network_name])
        row["docker_network"].update(id=network_id, creation_status="created")
        save()
        os.environ["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = network_name
        os.environ["KIND_EXPERIMENTAL_PROVIDER"] = "docker"
        identity()
        run([kind, "create", "cluster", "--name", name, "--kubeconfig", str(kubeconfig), "--config", str(config), "--wait", "120s"])
        row.update(creation_status="created", container_ids=owned_container())
        os.chmod(kubeconfig, 0o600)
        kube = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", "kind-" + name]
        objects = [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": {"peaso-test-owner": owner, "pod-security.kubernetes.io/enforce": "restricted"}}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name, "namespace": name}, "automountServiceAccountToken": False},
            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": name, "labels": {"app": name}},
             "spec": {"serviceAccountName": name, "automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
                      "containers": [{"name": "inert", "image": "registry.k8s.io/pause:3.10", "resources": {"requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"cpu": "25m", "memory": "16Mi"}},
                                      "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": name}, "spec": {"type": "ClusterIP", "selector": {"app": name}, "ports": [{"port": 9999, "targetPort": 9999}]}},
            {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": name}, "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": name, "namespace": name}, "rules": [{"apiGroups": [""], "resources": ["pods", "services"], "verbs": ["get", "list"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": name, "namespace": name}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
             "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": name}]},
        ]
        for obj in objects:
            obj["metadata"].setdefault("labels", {})["peaso-test-owner"] = owner
            entry = {"kind": obj["kind"], "name": name, "namespace": obj["metadata"].get("namespace"), "creation_status": "planned"}
            row["workload_resources"].append(entry)
            save()
            identity()
            context = run(kube + ["config", "view", "--minify", "-o", "json"], json_output=True)
            if context["current-context"] != "kind-" + name or not context["clusters"][0]["cluster"]["server"].startswith("https://127.0.0.1:") or not owned_container():
                raise RuntimeError("Kubernetes cluster identity mismatch")
            manifest = directory / (name + ".object.json")
            manifest.write_text(json.dumps(obj))
            created = run(kube + ["create", "-f", str(manifest), "-o", "json"], json_output=True)
            entry.update(creation_status="created", uid=created["metadata"]["uid"])
            save()
            manifest.unlink()
        request = {"connector": {"provider": "k8s", "name": "local-inert-qa", "auth": {"kubeconfig": str(kubeconfig), "context": "kind-" + name}, "scopes": [name]}}
        request_path = directory / "local-k8s-request.json"
        request_path.write_text(json.dumps(request))
        os.chmod(request_path, 0o600)
        run([sys.executable, "-m", "peaso.cli", "scan", "--request", str(request_path), "--snapshot-output", str(directory / "k8s-snapshot.json"), "--output", str(directory / "k8s-cli-report.json")])
        run([sys.executable, "-m", "peaso.cli", "evaluate", str(directory / "k8s-snapshot.json"), "--format", "markdown", "--output", str(directory / "k8s-cli-report.md")])
        snapshot = json.loads((directory / "k8s-snapshot.json").read_text())
        pod = next(c for c in snapshot["collections"] if c["type"] == "pod")
        assert any(item["metadata"]["name"] == name for item in pod["items"]), "Actual pod missing"
        report = json.loads((directory / "k8s-cli-report.json").read_text())
        print(json.dumps({"local_cluster": name, "resources": report["stats"]["resource_count"], "findings": report["stats"]["finding_count"], "provider": "local-k8s", "real_gke": False}))
    finally:
        identity()
        row["container_ids"] = owned_container()
        save()
        identity()
        run([kind, "delete", "cluster", "--name", name, "--kubeconfig", str(kubeconfig)])
        if owned_container():
            raise RuntimeError("Cluster container remains")
        kubeconfig.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
        network = row["docker_network"]
        if network["id"]:
            actual = run(["docker", "network", "inspect", network["id"]], json_output=True)[0]
            if actual["Name"] != network_name or actual.get("Labels", {}).get("peaso-test-owner") != owner or actual.get("Containers"):
                raise RuntimeError("Network ownership mismatch or attached containers")
            identity()
            run(["docker", "network", "rm", network["id"]])
            result = subprocess.run(["docker", "network", "inspect", network["id"]], capture_output=True, text=True)
            if result.returncode == 0 or "not found" not in result.stderr.lower():
                raise RuntimeError("Network absence not verified")
            network.update(creation_status="deleted", verification="not_found")
        for entry in row["workload_resources"]:
            entry.update(creation_status="deleted", verification="owning_cluster_not_found")
        row.update(creation_status="deleted", verification="cluster_containers_not_found_private_kubeconfig_removed")
        save()


if __name__ == "__main__":
    main()
