"""The documented read-only Data Factory token cannot run as its identity."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import load_catalog
from tests.test_peaso_privesc_schema_ext import entry, reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


TECHNIQUE = "azure-datafactory-dataplane-access-token"
ACTION = "Microsoft.DataFactory/factories/getDataPlaneAccess/action"
FACTORY = RG + "/providers/Microsoft.DataFactory/factories/finance"


def test_read_only_token_action_is_absent_from_active_escalation_catalog():
    entries = load_catalog(strict=True)["entries"]
    assert TECHNIQUE not in {entry["id"] for entry in entries}
    snap = az(assignments=[("u-alice", "User", FACTORY, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])},
              graph=[{"id": FACTORY, "type": "Microsoft.DataFactory/factories",
                      "identity": {"type": "SystemAssigned", "principalId": "mi-finance"}}])
    result = privesc.analyze(snap, entries=entries)
    assert reached(result, "u-alice", TECHNIQUE) == {}


def test_historical_entry_cannot_revive_the_read_only_token_edge():
    historical = entry(TECHNIQUE, "azure", {"all_of": [{"action": ACTION, "scope": "{target.scope}"}]},
                       {"kind": "azure_managed_identity",
                        "selector": {"azure_challenge_fact": TECHNIQUE},
                        "scope": "inherited_scope", "outcome": "credentials"})
    fact = {"TechniqueId": TECHNIQUE, "SourceId": "u-alice",
            "TargetKind": "azure_managed_identity", "TargetId": "mi-finance",
            "TargetScope": FACTORY, "Status": "verified"}
    snap = az(assignments=[("u-alice", "User", FACTORY, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])},
              graph=[{"id": FACTORY, "type": "Microsoft.DataFactory/factories",
                      "identity": {"type": "SystemAssigned", "principalId": "mi-finance"}}],
              extra=[("azure_privesc_challenge_evidence", FACTORY, [fact])])
    assert reached(privesc.analyze(snap, entries=[historical], include_unknown=True),
                   "u-alice", TECHNIQUE) == {}
