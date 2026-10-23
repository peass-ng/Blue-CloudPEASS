"""Recoverable snapshots are listed through the beta API with exact IAM reads."""

from peaso.collectors.gcp import GCPCollector


PROJECT = "projects/p1"
NAME = "deleted-abc"
BASE = "https://compute.googleapis.com/compute/beta/" + PROJECT + "/global/recoverableSnapshots"


def test_recoverable_snapshot_list_and_policy_read_are_bound_to_the_same_name():
    collector = GCPCollector({"scopes": [PROJECT], "options": {
        "inventories": ["recoverable_snapshot"], "concurrency": 1, "hydration_concurrency": 1}},
        ["recoverable_snapshot"], transport=object())
    collector.discover = lambda: None
    reads = []

    def pages(url, scope, **kwargs):
        reads.append(("list", url))
        yield ([{"name": NAME, "selfLink": BASE + "/" + NAME, "status": "READY"}], "list-read")

    def hydrate(item, field, url, scope, **kwargs):
        reads.append((field, url))
        return {**item, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}

    collector.pages = pages
    collector.hydrate = hydrate
    result = collector.collect()
    rows = next(c for c in result["collections"] if c["type"] == "recoverable_snapshot")
    assert reads == [("list", BASE), ("iamPolicy", BASE + "/" + NAME + "/getIamPolicy")]
    assert rows["status"] == "collected"
    assert rows["items"][0]["name"] == NAME
    assert rows["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
