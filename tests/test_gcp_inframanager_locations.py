"""Infra Manager location collection binds project-visible API locations."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace


def collection_pages(collector, scope):
    root = Path(__file__).resolve().parents[1] / "peaso/collectors"
    package = ModuleType("isolated_inframanager_collector")
    package.__path__ = [str(root)]
    gcp = ModuleType("isolated_inframanager_collector.gcp")
    gcp.ReadError = type("ReadError", (Exception,), {})
    names = ("isolated_inframanager_collector", "isolated_inframanager_collector.gcp",
             "isolated_inframanager_collector.gcp_inframanager_locations")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        sys.modules[names[0]] = package
        sys.modules[names[1]] = gcp
        spec = importlib.util.spec_from_file_location(names[2], root / "gcp_inframanager_locations.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[names[2]] = module
        spec.loader.exec_module(module)
        yield from module.collection_pages(collector, scope)
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


def test_reads_project_visible_locations_without_synthesizing_regions():
    scope = "projects/demo-project1"
    location = scope + "/locations/us-central1"
    def pages(url, requested_scope, **kwargs):
        assert url == "https://config.googleapis.com/v1/" + scope + "/locations"
        assert requested_scope == scope and kwargs["key"] == "locations"
        yield [{"name": location}], "receipt"
    collector = SimpleNamespace(pages=pages)
    assert list(collection_pages(collector, scope)) == [([{"name": location}], "receipt")]


def test_foreign_or_duplicate_location_is_rejected():
    scope = "projects/demo-project1"
    for names in (["projects/other/locations/us-central1"],
                  [scope + "/locations/us-central1"] * 2):
        def pages(url, requested_scope, **kwargs):
            yield [{"name": name} for name in names], "receipt"
        collector = SimpleNamespace(pages=pages)
        try:
            list(collection_pages(collector, scope))
        except Exception as exc:
            assert "inframanager_location_identity_unbound" in str(exc)
        else:
            raise AssertionError("unbound location was accepted")
