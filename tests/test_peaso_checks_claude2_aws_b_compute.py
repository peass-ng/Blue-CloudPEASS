"""Helper behaviour tests for the claude2_aws_b compute group."""
from peaso.checks import CHECKS
from peaso.checks import claude2_aws_b_compute as m

REGISTRY = {check.id: check for check in CHECKS}


def _status(cid, item, index=None):
    return REGISTRY[cid].evaluate(item, index or {})[0]


def test_eks_version_compares_numerically():
    assert _status("aws.c2b.eks.version_at_least_1_19", m._eks(version="1.9")) == "FAIL"
    assert _status("aws.c2b.eks.version_at_least_1_19", m._eks(version="1.100")) == "PASS"
    assert _status("aws.c2b.eks.version_at_least_1_28", m._eks(version="v1.28")) == "UNKNOWN"


def test_vpc_cni_configuration_parsing():
    cid = "aws.c2b.eks.vpc_cni_network_policy"
    assert _status(cid, m._cni('{"enableNetworkPolicy": "True"}')) == "PASS"
    assert _status(cid, m._cni('{"enableNetworkPolicy": false}')) == "FAIL"
    assert _status(cid, m._cni("not json")) == "MANUAL"
    assert _status(cid, m._cni("[1]")) == "MANUAL"


def test_fargate_platform_family():
    cid = "aws.c2b.ecs.fargate_latest_platform"
    assert _status(cid, m._svc(launchType="FARGATE", platformVersion="1.0.0", platformFamily="WINDOWS_SERVER_2022_FULL")) == "PASS"
    assert _status(cid, m._svc(launchType="FARGATE", platformVersion="1.3.0")) == "UNKNOWN"


def test_appstream_idle_omitted_is_disabled():
    item = {k: v for k, v in m.FLEET.items() if k != "IdleDisconnectTimeoutInSeconds"}
    assert _status("aws.c2b.appstream.idle_disconnect_10m", item) == "FAIL"


def test_collector_facts_shape():
    for fact in m.COLLECTOR_FACTS:
        assert set(fact) == {"kind", "api", "fields", "checks"} and fact["fields"] and fact["checks"]
