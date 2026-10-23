"""Image IAM policy reads provide exact evidence for prospective self-grants."""

import sys
import types
from pathlib import Path


def test_image_policy_is_hydrated_read_only(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    requests = []

    class Transport:
        def request(self, method, url, **kwargs):
            requests.append((method, url))
            if url.endswith("/global/images"):
                return {"items": [{
                    "name": "base-image", "status": "READY",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/p1/global/images/base-image"}]}, "image-list"
            if url.endswith("/global/images/base-image/getIamPolicy"):
                return {"etag": "ACAB", "bindings": []}, "image-policy"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": ["projects/p1"], "options": {
        "inventories": ["image"], "include_inherited": False, "concurrency": 1}}, transport=Transport())
    kind, scope, service, factory = next(job for job in collector.scope_jobs("projects/p1") if job[0] == "image")
    row = collector.envelope(kind, scope, service, factory)
    assert len(row["items"]) == 1
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert row["items"][0]["iamPolicy"]["bindings"] == []
    assert ("GET", "https://compute.googleapis.com/compute/v1/projects/p1/global/images/base-image/getIamPolicy") in requests
