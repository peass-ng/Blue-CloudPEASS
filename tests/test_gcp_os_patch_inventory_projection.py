"""Keep OS identity needed to decide patch job support."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType


def test_native_inventory_keeps_os_identity_and_agent_version(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_os_patch_projection")
    package.__path__ = [str(root)]
    gcp = ModuleType(package.__name__ + ".gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, gcp.__name__, gcp)
    name = package.__name__ + ".gcp_compliance_wave"
    spec = importlib.util.spec_from_file_location(name, root / "gcp_compliance_wave.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    expected = "projects/p1/locations/us-central1-a/instances/123/inventory"
    projected = module.normalize_os_inventory({
        "name": expected, "updateTime": "2026-10-22T10:30:00Z", "items": {},
        "osInfo": {"shortName": "ubuntu", "longName": "Ubuntu 22.04 LTS",
                   "version": "22.04", "osconfigAgentVersion": "20220427.00",
                   "hostname": "private-name"}}, "projects/p1", "vm", expected)
    assert projected["osInfo"] == {"shortName": "ubuntu", "longName": "Ubuntu 22.04 LTS",
                                   "version": "22.04", "osconfigAgentVersion": "20220427.00"}
