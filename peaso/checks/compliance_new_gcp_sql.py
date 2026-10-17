"""Signed Cloud SQL deletion-protection predicate over cached instance facts."""
from __future__ import annotations

from . import register, result
from .facts import complete_items, get
from .fixtures import CASES


@register(
    "gcp.sql.deletion_protection", "gcp", "hardening", "sql_instance",
    "Cloud SQL instance explicitly enables deletion protection", "medium", "CP-9",
    "Review the instance owner and enable deletion protection on the Cloud SQL instance.",
    dependencies=["sql_instance"],
)
def sql_deletion_protection(item, index):
    # A partial instances.list can contain individual rows while omitting
    # other instances. Do not emit an all-clear resource finding from it.
    complete_items(index, "sql_instance")
    name = get(item, "name", str)
    enabled = get(item, "settings.deletionProtectionEnabled", bool)
    return result(not enabled, sql_instance=name, deletion_protection_enabled=enabled,
                  field="settings.deletionProtectionEnabled")


def _sql_index(row, status="collected"):
    return {"collections": {"sql_instance": [{"scope": "projects/inert",
        "status": status, "items": [row]}]},
        "sql_instance": [{"data": row}]}


_sql_safe = {"name": "inert-sql", "settings": {"deletionProtectionEnabled": True}}
_sql_unsafe = {"name": "inert-sql", "settings": {"deletionProtectionEnabled": False}}
CASES["gcp.sql.deletion_protection"] = {
    "pass": _sql_safe, "pass_index": _sql_index(_sql_safe),
    "fail": _sql_unsafe, "fail_index": _sql_index(_sql_unsafe),
    "unknown": _sql_safe, "unknown_index": _sql_index(_sql_safe, "partial"),
    "index": _sql_index(_sql_safe)}
