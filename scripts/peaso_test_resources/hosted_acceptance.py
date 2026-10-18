"""Bounded hosted acceptance using only owned free identities and audit role."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit, unquote
import uuid

import httpx

ORIGIN = "https://cspm.hacktricks.wiki"
BUCKET = "hacktricks-cspm-artifacts-202533532952"


class HostedQA:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        identities = json.loads((self.root / "hosted-test-identities.json").read_text())
        owned = json.loads((self.root / "cognito-ledger.json").read_text())
        self.users = identities["users"]
        expected = {r["sub"] for r in owned["resources"] if r["creation_status"] == "created" and r["account"] == "202533532952"}
        if {u["sub"] for u in self.users} != expected:
            raise RuntimeError("Private identity/ledger subjects differ")
        self.role = next(r for r in json.loads((self.root / "audit-role-ledger.json").read_text())["resources"] if r["kind"] == "iam_role" and r["creation_status"] == "created")
        self.ledger = self.root / "hosted-data-ledger.json"
        self.data = json.loads(self.ledger.read_text()) if self.ledger.exists() else {"schema_version": 1, "task_id": "task_02a312b5ac1f", "resources": []}
        if self.data["task_id"] != "task_02a312b5ac1f":
            raise RuntimeError("Wrong data ledger")
        self.clients = [httpx.Client(base_url=ORIGIN, timeout=60, headers={"Authorization": "Bearer " + u["id_token"], "Origin": ORIGIN}) for u in self.users]
        self.summary = {"origin": ORIGIN, "gates": {}}
        for user in self.users:
            if not any(r.get("tenant") == user["sub"] for r in self.data["resources"]):
                self.data["resources"].append({"provider": "hosted-tenant-data", "account": "202533532952", "project": "hacktricks-cspm", "subscription": None,
                    "region": "us-east-1", "id": user["sub"], "name": "peaso-test-tenant-" + user["sub"], "tenant": user["sub"],
                    "creation_status": "planned", "delete_operation": "delete only exact tenant PK rows and exact owned scan artifact keys after jobs terminal",
                    "verification": "pending", "api_objects": [], "dynamodb_table": "hacktricks-cspm", "artifact_bucket": BUCKET})
        self.save()  # Before /api/me may create its free server entitlement cache.

    def save(self):
        self.ledger.write_text(json.dumps(self.data, indent=2) + "\n")
        os.chmod(self.ledger, 0o600)

    def identity(self, index):
        response = self.clients[index].get("/api/me")
        if response.status_code != 200:
            raise RuntimeError("Own hosted identity rejected: HTTP " + str(response.status_code))
        info = response.json()
        if info["tenant_id"] != self.users[index]["sub"] or info["plan"] != "free" or info["weekly_limit"] != 1:
            raise RuntimeError("Expected exact owned free subject")
        return info

    def request(self, index, method, route, *, expected=200, **kwargs):
        if method.lower() in {"post", "patch", "delete"}:
            self.identity(index)
        result = self.clients[index].request(method, route, **kwargs)
        if result.status_code != expected:
            raise RuntimeError(f"{method} {route}: expected {expected}, got {result.status_code}")
        return result

    def create(self, index, kind, body, *, headers=None):
        tenant = self.users[index]["sub"]
        row = next(r for r in self.data["resources"] if r["tenant"] == tenant)
        entry = {"kind": kind, "name": body.get("name", "peaso-test-" + kind), "id": None, "creation_status": "planned"}
        row["api_objects"].append(entry)
        self.save()
        value = self.request(index, "POST", "/api/" + kind, expected=201, json=body, **({"headers": headers} if headers else {})).json()
        entry.update(id=value["id"], creation_status="created")
        row["creation_status"] = "created"
        self.save()
        return value

    def aws_connector(self, index):
        value = self.create(index, "connectors", {"name": "peaso-test-hosted-aws-" + uuid.uuid4().hex[:10], "provider": "aws",
            "scopes": ["947247140022"], "auth": {"method": "assume_role", "role_arn": self.role["id"]},
            "options": {"regions": ["us-east-1"], "max_calls": 300, "max_pages": 3, "max_resources": 10000}})
        external = value["onboarding"]["external_id"]
        script = Path(__file__).with_name("update_audit_trust.py")
        subprocess.run([sys.executable, str(script), "--ledger", str(self.root / "audit-role-ledger.json"), "--external-id", external],
                       check=True, timeout=120, env={**os.environ, "PYTHONPATH": str(script.parents[2])})
        return value

    def azure_connector(self, index):
        subscription = "cfbcdcf4-cb4f-4e4e-9f3e-a6b3b3abadfc"
        tenant = "fdd066e1-ee37-49bc-b08f-d0e152119b04"
        selected = json.loads(subprocess.check_output(["az", "account", "show", "--subscription", subscription, "-o", "json"], text=True))
        if selected["id"] != subscription or selected["tenantId"] != tenant:
            raise RuntimeError("Azure customer identity scope changed")
        from azure.identity import AzureCliCredential
        credential = AzureCliCredential(tenant_id=tenant)
        try:
            arm = credential.get_token("https://management.azure.com/.default").token
            graph = credential.get_token("https://graph.microsoft.com/.default").token
        finally:
            credential.close()
        self.azure_tokens = (arm, graph)
        return self.create(index, "connectors", {"name": "peaso-test-hosted-azure", "provider": "azure", "scopes": [subscription],
            "auth": {"method": "token", "tenant_id": tenant, "arm_token": arm, "graph_token": graph},
            "options": {"collect_all": True, "max_calls": 500, "max_pages": 3, "max_resources": 20000}})

    def wait(self, index, scan):
        deadline = time.monotonic() + 600
        seen = []
        while time.monotonic() < deadline:
            job = self.request(index, "GET", "/api/scans/" + scan).json()
            if not seen or seen[-1] != job["status"]:
                seen.append(job["status"])
            if job["status"] in {"completed", "failed", "cancelled", "timed_out"}:
                self.summary["status_transitions"] = seen
                if job["status"] != "completed":
                    raise RuntimeError("Owned real scan ended " + job["status"])
                return job
            time.sleep(2)
        raise RuntimeError("Owned real scan did not complete within bounded wait")

    def download(self, index, scan, format):
        response = self.request(index, "GET", f"/api/scans/{scan}/report?format={format}")
        if response.headers.get("content-type", "").startswith("application/json") and "download_url" in response.json():
            url = response.json()["download_url"]
            parsed = urlsplit(url)
            allowed = {BUCKET + ".s3.amazonaws.com", BUCKET + ".s3.us-east-1.amazonaws.com"}
            prefix = "/artifacts/" + hashlib.sha256(self.users[index]["sub"].encode()).hexdigest() + "/" + scan + "/"
            if parsed.scheme != "https" or parsed.hostname not in allowed or not unquote(parsed.path).startswith(prefix):
                raise RuntimeError("Signed download is outside owned exact artifact scope")
            response = httpx.get(url, timeout=90, follow_redirects=False)
            if response.status_code != 200:
                raise RuntimeError("Owned signed download failed")
        path = self.root / ("hosted-report." + ("md" if format == "markdown" else "json"))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(response.content)
        return response

    def run(self):
        for index in range(len(self.users)):
            self.identity(index)
        self.summary["gates"]["existing_pool_id_jwt_free_identity"] = True
        with httpx.Client(base_url=ORIGIN, timeout=60, cookies={"__Secure-ht_refresh": self.users[1]["refresh_token"]}) as cookie:
            info = cookie.get("/api/me")
            assert info.status_code == 200 and info.json()["tenant_id"] == self.users[1]["sub"]
            refused = cookie.post("/api/connectors", json={"name": "peaso-test-csrf", "provider": "aws"})
            assert refused.status_code == 403
        self.summary["gates"]["existing_refresh_cookie_and_origin_enforcement"] = True
        connector = self.aws_connector(0)
        job = self.create(0, "scans", {"connector_id": connector["id"]}, headers={"Idempotency-Key": "peaso-test-real-aws"})
        scan = job["id"]
        self.wait(0, scan)
        report_response = self.download(0, scan, "json")
        report = report_response.json()
        markdown = self.download(0, scan, "markdown")
        assert report["provider"] == "aws" and report["resources"] and report["findings"]
        assert report["snapshot_id"] in markdown.text
        for user in self.users:
            for field in ("id_token", "refresh_token", "password"):
                assert user[field] not in report_response.text + markdown.text
        self.summary["gates"]["real_aws_scan_json_markdown_secrets_absent"] = True
        self.summary["real_scan"] = {"scan_id": scan, "resources": len(report["resources"]), "findings": len(report["findings"]), "coverage_complete": report["stats"]["coverage_complete"]}
        for route in (f"/api/connectors/{connector['id']}", f"/api/scans/{scan}", f"/api/scans/{scan}/report", f"/api/scans/{scan}/findings", f"/api/scans/{scan}/graphs/iam"):
            self.request(1, "GET", route, expected=404)
        self.request(1, "POST", f"/api/scans/{scan}/cancel", expected=404)
        self.request(0, "POST", "/api/scans", expected=429, json={"connector_id": connector["id"]})
        self.summary["gates"]["tenant_isolation_and_server_free_quota"] = True
        azure = self.azure_connector(1)
        azure_job = self.create(1, "scans", {"connector_id": azure["id"]})
        self.wait(1, azure_job["id"])
        large = self.download(1, azure_job["id"], "json")
        azure_report = large.json()
        azure_markdown = self.download(1, azure_job["id"], "markdown")
        assert azure_report["provider"] == "azure" and len(azure_report["resources"]) > 1000
        assert azure_report["snapshot_id"] in azure_markdown.text
        assert all(token not in large.text + azure_markdown.text for token in self.azure_tokens)
        fixture_ids = [value for key, value in os.environ.items() if key in {"PEASO_TEST_RESOURCE_GROUP", "PEASO_TEST_NSG", "PEASO_TEST_VNET"}]
        assert all(value in large.text for value in fixture_ids), "Hosted Azure missed disposable fixtures"
        pages = self.request(1, "GET", f"/api/scans/{azure_job['id']}/findings?limit=100&offset=0")
        assert len(pages.json()["items"]) <= 100 and len(pages.content) < 6 * 1024 * 1024
        graph_page = self.request(1, "GET", f"/api/scans/{azure_job['id']}/graphs/iam")
        assert len(graph_page.content) < 6 * 1024 * 1024
        self.request(0, "GET", f"/api/scans/{azure_job['id']}/report", expected=404)
        self.request(1, "POST", "/api/scans", expected=429, json={"connector_id": azure["id"]})
        self.summary["large_azure_scan"] = {"scan_id": azure_job["id"], "resources": len(azure_report["resources"]),
            "findings": len(azure_report["findings"]), "full_json_bytes": len(large.content), "markdown_bytes": len(azure_markdown.content),
            "findings_page_bytes": len(pages.content), "graph_projection_bytes": len(graph_page.content), "short_lived_tokens_absent": True}
        self.summary["gates"]["actual_large_azure_signed_download_pages_and_isolation"] = True
        schedule = self.create(0, "schedules", {"connector_id": connector["id"], "interval_hours": 168, "next_run_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()})
        self.request(0, "PATCH", "/api/schedules/" + schedule["id"], json={"enabled": False})
        self.request(0, "DELETE", "/api/schedules/" + schedule["id"], expected=204)
        self.summary["gates"]["schedule_create_pause_delete"] = True
        other = self.aws_connector(2)
        cancelled = self.create(2, "scans", {"connector_id": other["id"]})
        result = self.request(2, "POST", "/api/scans/" + cancelled["id"] + "/cancel").json()
        assert result["status"] == "cancelled"
        self.request(2, "GET", "/api/scans/" + cancelled["id"] + "/report", expected=409)
        self.summary["gates"]["cancellation"] = True
        self.summary["limitations"] = ["Public Turnstile login/register submit not claimed by administrative fixture creation.", "No genuine paid subscription credentials: live paid10 quota not tested.", "Real GCP/GKE auth pending separately."]
        path = self.root / "hosted-summary.json"
        path.write_text(json.dumps(self.summary, indent=2))
        os.chmod(path, 0o600)
        print(json.dumps(self.summary, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    qa = HostedQA(args.directory)
    try:
        qa.run()
    finally:
        for client in qa.clients:
            client.close()


if __name__ == "__main__":
    main()
