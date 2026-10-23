"""Password Administrator resets use the narrow target-role matrix."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_helpdesk_password_reset import _case as helpdesk_case


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-reset-password-password-admin")


def _case(**kwargs):
    snap = helpdesk_case(**kwargs)
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs["items"][0]["displayName"] = "Password Administrator"
    return snap


def _targets(snap, *, app=False):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source" if app else "u-source", ENTRY["id"])


def test_password_admin_matrix_and_protected_owner():
    assert validate_entry(ENTRY)[0] == []
    for role in (None, "Directory Readers", "Guest Inviter", "Password Administrator"):
        assert "u-target" in _targets(_case(target_role=role))
    for role in ("Helpdesk Administrator", "Global Reader", "User Experience Success Manager"):
        assert "u-target" not in _targets(_case(target_role=role))
    assert "u-target" not in _targets(_case(owner=True))


def test_password_admin_scope_and_restricted_unit():
    assert "u-target" in _targets(_case(source_scope="/administrativeUnits/au-1"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-2"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-1",
                                            target_role="Directory Readers"))
    assert "u-target" not in _targets(_case(restricted=True))
    assert "u-target" in _targets(_case(restricted=True, source_scope="/administrativeUnits/au-1"))


def test_password_origin_and_incomplete_owner_evidence():
    assert "u-target" not in _targets(_case(federated=True))
    assert _targets(_case(synced=True))["u-target"] == "conditional"
    assert "u-target" not in _targets(_case(app=True), app=True)
    snap = _case()
    next(c for c in snap["collections"] if c["type"] == "directory_owner")["status"] = "partial"
    assert _targets(snap)["u-target"] == "conditional"
