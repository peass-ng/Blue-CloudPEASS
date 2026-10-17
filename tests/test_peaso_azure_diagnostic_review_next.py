"""Adversarial scope-boundary review for diagnostic inventory completion."""
from types import SimpleNamespace

from peaso.collectors import azure


SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"


def test_sibling_subscription_child_does_not_suppress_requested_envelope():
    sibling = SCOPE + "0"
    foreign_child = {
        "type": "diagnostic_setting",
        "scope": sibling + "/resourceGroups/rg/providers/Microsoft.Web/sites/app",
        "service": "Microsoft.Insights",
        "status": "denied",
        "items": [],
    }
    parents = [
        {"type": kind, "scope": SCOPE, "service": "azure", "status": "empty", "items": []}
        for kind in set(azure.ENDPOINTS) - azure.NO_DIAGNOSTIC_KINDS
    ]
    reader = SimpleNamespace(collections=parents + [foreign_child])

    azure._complete_diagnostic_inventory(reader, [SCOPE])

    children = [row for row in reader.collections if row["type"] == "diagnostic_setting"]
    assert len(children) == 2
    assert foreign_child in children
    assert next(row for row in children if row["scope"] == SCOPE) == {
        "type": "diagnostic_setting",
        "scope": SCOPE,
        "service": "Microsoft.Insights",
        "status": "empty",
        "items": [],
        "parent_inventory": "diagnostic_resource_universe",
    }
