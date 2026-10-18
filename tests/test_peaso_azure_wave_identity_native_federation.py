"""Directed staged SW20 federation evaluator regression cases."""
import importlib

from tests.compliance_draft_isolation import staged_registry


def _fixture():
    with staged_registry(["compliance_new_sw20"]):
        return importlib.import_module("tests.test_peaso_compliance_new_sw20")


def test_correlated_direct_signin_fails_even_if_domain_now_managed():
    fx = _fixture()
    snapshot = fx.build(fx.sw.FEDERATED, bad=True)
    fx.first(snapshot, "domain_federation")["authenticationType"] = "Managed"
    status, evidence = fx.evaluate(fx.sw.FEDERATED, snapshot)
    assert status == "FAIL", evidence
    assert evidence["outcomes"][0]["outcomes"][0]["sign_in_id"] == "signin-1"


def test_approved_history_requires_current_federation_for_pass():
    fx = _fixture()
    snapshot = fx.build(fx.sw.FEDERATED)
    assert fx.evaluate(fx.sw.FEDERATED, snapshot)[0] == "PASS"
    fx.first(snapshot, "domain_federation")["authenticationType"] = "Managed"
    status, evidence = fx.evaluate(fx.sw.FEDERATED, snapshot)
    assert status == "UNKNOWN", evidence
    assert "current approved federation configuration unavailable" in evidence["outcomes"][0]["reason"]


def test_uncorrelated_direct_claim_is_unknown():
    fx = _fixture()
    snapshot = fx.build(fx.sw.FEDERATED, bad=True)
    fx.first(snapshot, "human_signin_history")["authenticationEvidence"][0]["correlationId"] = "wrong"
    status, evidence = fx.evaluate(fx.sw.FEDERATED, snapshot)
    assert status == "UNKNOWN", evidence
    assert "authentication issuer correlation unresolved" in evidence["outcomes"][0]["outcomes"][0]["reason"]
