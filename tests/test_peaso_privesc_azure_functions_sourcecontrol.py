"""Function source-control edits require the exact child operation and host."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-functions-sites-write-source-control"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
APP = f"{RG}/providers/Microsoft.Web/sites/function-app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other-app"
SOURCE = "Microsoft.Web/sites/sourcecontrols/write"
SITE = "Microsoft.Web/sites/write"
START = "Microsoft.Web/sites/start/action"


def _run(*, grants=None, kind="functionapp", state="Running", include_unknown=False):
    grants = grants if grants is not None else [(SOURCE, APP + "/sourcecontrols/web")]
    app = {"id": APP, "type": "Microsoft.Web/sites", "kind": kind,
           "properties": {"state": state}, "identity": {"principalId": "mi-app"}}
    other = {"id": OTHER, "type": "Microsoft.Web/sites", "kind": "functionapp",
             "properties": {"state": "Running"}, "identity": {"principalId": "mi-other"}}
    assignments = [("u-alice", "User", scope, f"role-{i}")
                   for i, (_, scope) in enumerate(grants)]
    roles = {f"role-{i}": ([action], []) for i, (action, _) in enumerate(grants)}
    snap = az(assignments=assignments, roles=roles, graph=[app, other],
              extra=[("app_service", SUB, [app, other])])
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=include_unknown),
                   "u-alice", TID)


def test_exact_source_control_write_reaches_function_identity():
    assert validate_entry(ENTRY)[0] == []
    assert _run() == {"mi-app": "conditional"}
    assert _run(grants=[(SOURCE, APP)]) == {"mi-app": "conditional"}


def test_site_write_wrong_child_and_wrong_host_do_not_reach_identity():
    for grants in ([(SITE, APP)], [(SOURCE, APP + "/config/web")],
                   [(SOURCE, OTHER + "/sourcecontrols/web")]):
        assert "mi-app" not in _run(grants=grants)


def test_container_or_stopped_function_is_not_claimed_without_necessary_path():
    assert _run(kind="functionapp,container", include_unknown=True).get("mi-app") != "conditional"
    assert _run(state="Stopped", include_unknown=True).get("mi-app") != "conditional"
    assert _run(state="Stopped", grants=[(SOURCE, APP), (START, APP)]) == {
        "mi-app": "conditional"}
