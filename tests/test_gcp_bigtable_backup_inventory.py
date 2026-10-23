"""Bigtable backup inventory binds the exact source and records policy denial."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
BACKUP = INSTANCE + "/clusters/c1/backups/b1"


def collect(monkeypatch, *, denied=False, wrong_parent=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/instances"):
                return {"instances": [{"name": INSTANCE}]}, "instances"
            if url.endswith("/instances/i1:getIamPolicy"):
                return {"bindings": []}, "policy"
            if url.endswith("/clusters/-/backups"):
                assert "pageSize" in kwargs.get("params", {})
                name = BACKUP.replace("/instances/i1/", "/instances/other/") if wrong_parent else BACKUP
                return {"backups": [{"name": name,
                    "sourceTable": INSTANCE + "/tables/private", "state": "READY",
                    "expireTime": "2099-01-01T00:00:00Z",
                    "encryptionInfo": {"encryptionType": "GOOGLE_DEFAULT_ENCRYPTION"}}]}, "backups"
            if url.endswith("/backups/b1:getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigtable_backup"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    return {row["type"]: row for row in collector.collect()["collections"]
            if row["type"].startswith("bigtable_")}


def test_backup_and_instance_policy_are_collected(monkeypatch):
    rows = collect(monkeypatch)
    assert rows["bigtable_instance"]["status"] == "collected"
    backup, = rows["bigtable_backup"]["items"]
    assert backup["name"] == BACKUP
    assert backup["sourceTable"] == INSTANCE + "/tables/private"
    assert backup["_coverage"]["iamPolicy"]["status"] == "collected"


def test_denied_backup_policy_stays_denied(monkeypatch):
    backup, = collect(monkeypatch, denied=True)["bigtable_backup"]["items"]
    assert backup["_coverage"]["iamPolicy"]["status"] == "denied"


def test_wrong_instance_backup_is_malformed(monkeypatch):
    assert collect(monkeypatch, wrong_parent=True)["bigtable_backup"]["status"] == "malformed"
