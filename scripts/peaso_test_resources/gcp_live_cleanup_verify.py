"""Read-only final absence evidence, including truncated GKE node names."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from scripts.peaso_test_resources.gke_session_guard import PROJECT, Session, SessionError, private_write


def owned_generated_references(snapshot, ledger):
    refs = {}
    network = "https://www.googleapis.com/compute/v1/projects/" + PROJECT + "/global/networks/" + ledger["cluster"]
    def add(url, kind, identity=None, evidence=None):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in {"www.googleapis.com", "compute.googleapis.com"} or not parsed.path.startswith("/compute/v1/projects/" + PROJECT + "/"):
            raise SessionError("generated_reference_outside_authorized_project")
        refs[url] = {"kind": kind, "selfLink": url, "id": identity, "ownership_evidence": evidence}
    for collection in snapshot["collections"]:
        for item in collection["items"]:
            if collection["type"] == "instance" and item.get("labels", {}).get("peaso-owner") == ledger["owner"]:
                if not any(nic.get("network") == network for nic in item.get("networkInterfaces", [])):
                    raise SessionError("owned_node_network_mismatch")
                add(item["selfLink"], "instance", item.get("id"), "captured instance owner label and exact owned network")
                for disk in item.get("disks", []):
                    if disk.get("source"):
                        add(disk["source"], "disk", evidence="captured attachment on exact owned node")
            elif collection["type"] == "gke_cluster" and item.get("name") == ledger["cluster"]:
                if item.get("resourceLabels", {}).get("peaso-owner") != ledger["owner"]:
                    raise SessionError("captured_cluster_owner_mismatch")
                for pool in item.get("nodePools", []):
                    for ref in pool.get("instanceGroupUrls", []):
                        add(ref, "instance_group_manager", evidence="captured exact owned GKE node-pool reference")
                        add(ref.replace("/instanceGroupManagers/", "/instanceGroups/"), "instance_group",
                            evidence="associated Compute group for captured managed-group identity")
            elif collection["type"] == "route" and item.get("network") == network:
                add(item["selfLink"], "route", item.get("id"), "captured exact owned VPC association")
    return sorted(refs.values(), key=lambda row: row["selfLink"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    session = Session(args.directory)
    if session.data["phase"] != "cleaned":
        raise SessionError("primary_cleanup_not_complete")
    snapshot = json.loads((session.directory / "gke-provisioning-gcp-snapshot.json").read_text())
    later = json.loads((session.directory / "gke-gcp-snapshot.json").read_text())
    refs = {row["selfLink"]: row for row in owned_generated_references(snapshot, session.data)}
    refs.update({row["selfLink"]: row for row in owned_generated_references(later, session.data)})
    for row in refs.values():
        actual = session.api("GET", "compute.googleapis.com" + urlsplit(row["selfLink"]).path)
        if actual is not None:
            raise SessionError("generated_resource_still_present:" + row["kind"])
        row.update(status="deleted", verification="exact_resource_get_404")
    templates = []
    token = None
    while True:
        from urllib.parse import quote
        path = "compute.googleapis.com/compute/v1/projects/" + PROJECT + "/global/instanceTemplates?maxResults=500"
        if token:
            path += "&pageToken=" + quote(token, safe="")
        page = session.api("GET", path)
        for item in page.get("items", []):
            labels = item.get("properties", {}).get("labels", {})
            if labels.get("peaso-owner") == session.data["owner"]:
                templates.append(item.get("selfLink"))
        token = page.get("nextPageToken")
        if not token:
            break
    if templates:
        raise SessionError("owned_instance_template_remains")
    baseline = json.loads((session.directory / "default-kubeconfig-baseline.json").read_text())
    unchanged = True
    for item in baseline:
        path = Path(item["path"])
        current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        unchanged &= path.exists() == item["exists"] and current == item["sha256"]
    if not unchanged:
        raise SessionError("user_default_kubeconfig_changed")
    if session.kubeconfig.exists() or session.cluster() is not None:
        raise SessionError("private_kubeconfig_or_cluster_remains")
    for row in session.data["resources"]:
        if row["kind"] == "service_account" and session.service_account(row["email"]) is not None:
            raise SessionError("owned_service_account_remains")
    policy = session.project_policy()
    member = "serviceAccount:" + session.data["resources"][0]["email"]
    if any(member in b.get("members", []) for b in policy.get("bindings", [])):
        raise SessionError("owned_iam_membership_remains")
    evidence = {"verified_at": datetime.now(timezone.utc).isoformat(), "project": PROJECT,
                "primary_resources": session.data["resources"], "generated_resources": list(refs.values()),
                "owned_instance_templates_absent": True, "default_kubeconfig_unchanged": True,
                "private_kubeconfig_removed": True, "exact_node_role_member_absent": True,
                "semantics": "Read-only repeat verification; no resource deletion or IAM modification in this helper"}
    private_write(session.directory / "gke-cleanup-verification.json", evidence)
    session.data["additional_generated_verification"] = list(refs.values())
    session.data["default_kubeconfig_unchanged"] = True
    session.save()
    print(json.dumps({"cleanup_verified": True, "primary_resources": len(session.data["resources"]),
                      "additional_generated_resources": len(refs), "user_default_context_unchanged": True}))


if __name__ == "__main__":
    main()
