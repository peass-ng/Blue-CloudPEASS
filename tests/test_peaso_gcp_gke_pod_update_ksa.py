"""A Pod image update can use only the existing Pod's mounted KSA token."""
from peaso import privesc
from test_peaso_gcp_gke_pod_exec_ksa import TARGET, case as base_case

ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-pods-update-running-ksa")


def case(**kwargs):
    return base_case(action="container.pods.update", entry=ENTRY, **kwargs)


def test_running_pod_image_update_reaches_only_mounted_ksa_without_challenge_fact():
    assert case() == [(TARGET, "conditional")]
    assert case(legacy=True) == [(TARGET, "conditional")]
    assert case(token=False) == []
    assert case(mount=False) == []
    assert case(running=False) == []
    assert case(wrong_sa=True) == []
    assert case(legacy=True, legacy_uid="old-uid") == []
    assert case(audience="other-service")[0][1] == "unknown"


def test_missing_image_permission_or_inventory_does_not_claim_ksa():
    assert case(image="")[0][1] == "unknown"
    assert case(exec_permission=False) == []
    assert case(get=False) == []
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(pod_status="denied")[0][1] == "unknown"
    assert case(sa_status="denied")[0][1] == "unknown"
