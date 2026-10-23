"""Network Connectivity IAM reads stay on their named hub and child group."""
import pytest

from test_gcp_config_delivery_location import catalog


PROJECT = "projects/demo-project1"
HUB = PROJECT + "/locations/global/hubs/core"
GROUP = HUB + "/groups/default"
ROOT = "https://networkconnectivity.googleapis.com/v1"


class Collector:
    def __init__(self, group=GROUP):
        self.group = group
        self.urls = []

    def pages(self, url, scope, *, key=None, params=None):
        assert scope == PROJECT
        self.urls.append(url)
        if url == ROOT + "/" + PROJECT + "/locations/global/hubs":
            yield [{"name": HUB}], "hubs"
        elif url == ROOT + "/" + HUB + "/groups":
            yield [{"name": self.group}], "groups"
        else:
            raise AssertionError(url)

    def hydrate(self, item, field, url, scope, *, params=None):
        assert field == "iamPolicy"
        assert params == {"options.requestedPolicyVersion": 3}
        self.urls.append(url)
        return {**item, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}


def test_hub_and_group_policies_use_their_own_resource_paths():
    module = catalog()
    collector = Collector()
    hubs = list(module.network_connectivity_hubs(collector, PROJECT))
    groups = list(module.network_connectivity_hubs(collector, PROJECT, groups=True))
    assert hubs[-1][0][0]["name"] == HUB
    assert groups[-1][0][0]["name"] == GROUP
    assert ROOT + "/" + HUB + ":getIamPolicy" in collector.urls
    assert ROOT + "/" + GROUP + ":getIamPolicy" in collector.urls


def test_group_from_another_hub_is_rejected():
    module = catalog()
    def read_error_init(self, status, reason):
        self.status = status
        self.reason = reason
    module.ReadError.__init__ = read_error_init
    collector = Collector(GROUP.replace("/hubs/core/", "/hubs/other/"))
    with pytest.raises(module.ReadError):
        list(module.network_connectivity_hubs(collector, PROJECT, groups=True))
