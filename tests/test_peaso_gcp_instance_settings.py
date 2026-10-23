"""Read zonal metadata keys without retaining script content."""

from peaso.collectors.gcp import GCPCollector, ReadError


PROJECT = "projects/p1"
ZONE = "us-central1-a"
BASE = "https://www.googleapis.com/compute/v1/"


def collect_settings(*, denied=False):
    collector = GCPCollector({"scopes": [PROJECT],
                              "options": {"inventories": ["instance_settings"], "concurrency": 1}},
                             ["instance_settings"], transport=object())
    collector.discover = lambda: None
    vm = {"name": "vm1", "zone": BASE + f"{PROJECT}/zones/{ZONE}",
          "selfLink": BASE + f"{PROJECT}/zones/{ZONE}/instances/vm1", "status": "RUNNING"}
    collector.scope_jobs = lambda scope: [("instance", scope, "compute",
                                            lambda: iter([([vm], "vm-read")]))]
    reads = []

    def pages(url, scope, **kwargs):
        reads.append(url)
        if denied:
            raise ReadError("denied", "instance_settings_permission_denied")
        yield ([{"zone": BASE + f"{PROJECT}/zones/{ZONE}",
                "metadata": {"items": {"startup-script": "SECRET-CONTENT"}}}], "zone-read")

    collector.pages = pages
    snapshot = collector.collect()
    return next(row for row in snapshot["collections"] if row["type"] == "instance_settings"), reads, snapshot


def test_zonal_settings_are_requested_once_and_script_values_are_redacted():
    settings, reads, snapshot = collect_settings()
    assert reads == [f"https://compute.googleapis.com/compute/v1/{PROJECT}/zones/{ZONE}/instanceSettings"]
    assert settings["status"] == "collected"
    assert settings["items"][0]["metadata"]["items"] == [{"key": "startup-script"}]
    assert "SECRET-CONTENT" not in str(snapshot)


def test_denied_zone_read_is_recorded_as_missing_evidence():
    settings, _, _ = collect_settings(denied=True)
    assert settings["status"] == "denied"
    assert settings["items"] == []
