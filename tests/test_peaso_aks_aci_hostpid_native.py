"""Collector-to-engine hostPID precedence with native AKS and ACI inventories."""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, k8s
from peaso.engine import evaluate_snapshot
from tests.test_peaso_azure_aks_workloads_native import ca, fixture, RID, SCOPE, SUB
from tests.test_peaso_azure_bulk_native import Transport, parent


CONTROL = "azure_aks_cluster_1_4_5_2_3ac7b3c"
ACI = SCOPE + "/resourceGroups/rg/providers/Microsoft.ContainerInstance/containerGroups/group"
ACI_LIST = SCOPE + "/providers/Microsoft.ContainerInstance/containerGroups"


def native_result(ca, monkeypatch, *, host_pid=False, aci=False, mode="good", pod_present=True, tamper=None):
    routes, responses, options, auth, Api = fixture(ca, mode)
    routes[SCOPE] = {"id": SCOPE, "subscriptionId": SUB, "tenantId": Transport.tenant}
    if pod_present:
        responses["/api/v1/pods"][0]["spec"]["hostPID"] = host_pid
    else:
        responses["/api/v1/pods"] = []
    if aci:
        group = parent(ACI, "Microsoft.ContainerInstance/containerGroups", {
            "containers": [{"name": "c", "properties": {"image": "example.azurecr.io/app:v1"}}],
            "osType": "Linux", "provisioningState": "Succeeded"})
        routes[ACI_LIST] = {"value": [deepcopy(group)]}
        routes[ACI] = group
    arm = Transport(routes)
    monkeypatch.setattr(k8s, "_new_api", lambda context: Api())
    snapshot = azure.collect({"auth": auth, "options": options, "scopes": [SUB]},
                             ["pod", "container_group"], transport=arm)
    if tamper is not None:
        tamper(snapshot)
        snapshot.pop("snapshot_id", None)
    report = evaluate_snapshot(snapshot, checks=[CONTROL], include_not_applicable=True)
    status = report["findings"][0]["status"]
    envelopes = {c["type"]: c for c in snapshot["collections"]
                 if c["type"] in ("pod", "container_group")}
    return status, envelopes, arm


@pytest.mark.parametrize("host_pid,aci,expected", [
    (False, False, "PASS"),
    (True, False, "FAIL"),
    (False, True, "UNKNOWN"),
    (True, True, "FAIL"),
])
def test_native_hostpid_precedence(ca, monkeypatch, host_pid, aci, expected):
    status, inventories, arm = native_result(ca, monkeypatch, host_pid=host_pid, aci=aci)
    assert inventories["pod"]["status"] == "collected"
    assert inventories["container_group"]["status"] == ("collected" if aci else "empty")
    assert inventories["pod"]["items"][0]["_provenance"]["representation"] == "full"
    if aci:
        assert "hostProcessEvidence" not in inventories["container_group"]["items"][0]
        assert any(urlsplit(url).path == ACI for url in arm.calls)
    assert status == expected


def test_partial_native_pod_pages_remain_unknown(ca, monkeypatch):
    status, inventories, _ = native_result(ca, monkeypatch, host_pid=True, mode="partial")
    assert inventories["pod"]["status"] not in ("collected", "empty")
    assert status == "UNKNOWN"


def test_aci_only_remains_unknown_without_a_native_hostpid_fact(ca, monkeypatch):
    status, inventories, _ = native_result(ca, monkeypatch, aci=True, pod_present=False)
    assert inventories["pod"]["status"] == "empty"
    assert inventories["container_group"]["status"] == "collected"
    assert status == "UNKNOWN"


@pytest.mark.parametrize("replacement", [
    "k8s://%2Fsubscriptions%2Fforeign%2Fresourcegroups%2Frg%2Fproviders%2Fmicrosoft.containerservice%2Fmanagedclusters%2Fcluster/pod/default/Pod-app",
    "k8s://%2Fsubscriptions%2F11111111-1111-1111-1111-111111111111%2Fresourcegroups%2Frg%2Fproviders%2Fmicrosoft.containerservice%2Fmanagedclusters%2Fcluster/pod/default/wrong-uid",
])
def test_tampered_pod_identity_cannot_prove_failure(ca, monkeypatch, replacement):
    def tamper(snapshot):
        pod = next(c for c in snapshot["collections"] if c["type"] == "pod")
        pod["items"][0]["id"] = replacement
    status, _, _ = native_result(ca, monkeypatch, host_pid=True, tamper=tamper)
    assert status == "UNKNOWN"
