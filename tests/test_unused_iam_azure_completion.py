from peaso.collectors import azure_unused_iam_completion as collect
from peaso import unused_iam_azure_completion as evaluate

TENANT = "11111111-1111-4111-8111-111111111111"
SUB = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"
APP = "44444444-4444-4444-8444-444444444444"
FIC = "55555555-5555-4555-8555-555555555555"
IDENTITY = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/job"
RESOURCE = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
NOW = "2026-10-21T12:00:00Z"


class Reader:
    def __init__(self, pages):
        self.values = pages
        self.calls = []

    def pages(self, request, url, *, audience, next_key):
        self.calls.append((url, audience, next_key))
        yield from self.values


def test_user_success_only_and_no_backfill_inference():
    row = {"id": USER, "displayName": "Alex", "accountEnabled": True,
           "signInActivity": {"lastSignInDateTime": "2026-10-20T00:00:00Z",
                              "lastSuccessfulSignInDateTime": "2026-01-01T00:00:00Z"}}
    receipt = collect.collect_user_success(Reader([[row]]), None, tenant=TENANT, context="one")
    status, detail = evaluate.evaluate_user_success(receipt["items"][0], tenant=TENANT,
        context="one", captured_at=NOW, receipt=receipt)
    assert status == "FAIL" and detail["days_since_success"] > 90
    row["signInActivity"].pop("lastSuccessfulSignInDateTime")
    receipt = collect.collect_user_success(Reader([[row]]), None, tenant=TENANT, context="one")
    assert evaluate.evaluate_user_success(receipt["items"][0], tenant=TENANT,
        context="one", captured_at=NOW, receipt=receipt)[0] == "UNKNOWN"
    row["signInActivity"]["lastSuccessfulSignInDateTime"] = "2026-10-01T00:00:00Z"
    receipt = collect.collect_user_success(Reader([[row]]), None, tenant=TENANT, context="one")
    assert evaluate.evaluate_user_success(receipt["items"][0], tenant=TENANT,
        context="one", captured_at=NOW, receipt=receipt)[0] == "PASS"


def test_user_partial_denied_and_foreign_capture():
    class Denied(Reader):
        def pages(self, *args, **kwargs):
            error = RuntimeError("forbidden")
            error.status_code = 403
            raise error
            yield
    receipt = collect.collect_user_success(Denied([]), None, tenant=TENANT, context="one")
    assert evaluate.evaluate_user_success({"id": USER}, tenant=TENANT, context="one",
        captured_at=NOW, receipt=receipt)[0] == "DENIED"
    assert evaluate.evaluate_user_success({"id": USER}, tenant=TENANT, context="other",
        captured_at=NOW, receipt=receipt)[0] == "UNKNOWN"


def test_managed_identity_positive_assignment_and_empty_unknown():
    identity = {"id": IDENTITY, "properties": {"principalId": USER}}
    receipt = collect.collect_arm_assignments(Reader([[{"id": RESOURCE,
        "identity": {"userAssignedIdentities": {IDENTITY: {"principalId": USER}}}}]]),
        None, tenant=TENANT, context="one", subscription=SUB)
    assert evaluate.evaluate_managed_identity_consumers(identity, tenant=TENANT,
        context="one", receipt=receipt)[0] == "PASS"
    empty = collect.collect_arm_assignments(Reader([[]]), None, tenant=TENANT,
        context="one", subscription=SUB)
    assert evaluate.evaluate_managed_identity_consumers(identity, tenant=TENANT,
        context="one", receipt=empty)[0] == "UNKNOWN"


def test_federated_trust_is_inventory_not_usage():
    parent = {"id": APP}
    row = {"id": FIC, "issuer": "https://issuer.example", "subject": "repo:owner/name:ref:refs/heads/main",
           "audiences": ["api://AzureADTokenExchange"]}
    reader = Reader([[row]])
    receipt = collect.collect_federated_credentials(reader, None, parent, tenant=TENANT, context="one")
    assert reader.calls == [(collect.GRAPH + "/v1.0/applications/" + APP + "/federatedIdentityCredentials",
                             collect.GRAPH, "@odata.nextLink")]
    status, detail = evaluate.evaluate_federated_credentials(parent, tenant=TENANT,
        context="one", receipt=receipt)
    assert status == "UNKNOWN" and detail["credentials"][0]["id"] == FIC
    empty = collect.collect_federated_credentials(Reader([[]]), None, parent,
        tenant=TENANT, context="one")
    assert evaluate.evaluate_federated_credentials(parent, tenant=TENANT,
        context="one", receipt=empty)[0] == "NOT_APPLICABLE"


def test_managed_federation_rejects_foreign_child():
    parent = {"id": IDENTITY}
    foreign = {"id": RESOURCE + "/federatedIdentityCredentials/elsewhere",
        "properties": {"issuer": "https://issuer.example", "subject": "s", "audiences": ["a"]}}
    receipt = collect.collect_federated_credentials(Reader([[foreign]]), None, parent,
        tenant=TENANT, context="one", managed=True)
    assert receipt["status"] == "unknown"
    assert evaluate.evaluate_federated_credentials(parent, tenant=TENANT,
        context="one", receipt=receipt, managed=True)[0] == "UNKNOWN"
