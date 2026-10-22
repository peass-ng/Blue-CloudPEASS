"""An App Service UAMI edge needs one exact writable, code-controllable site."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az, _uami


TID = "azure-appservice-assign-user-assigned-identity"
APP = f"{RG}/providers/Microsoft.Web/sites/app"
OTHER = f"{RG}/providers/Microsoft.Web/sites/other"
UAMI = _uami("power", "mi-power")
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action"
WRITE = "Microsoft.Web/sites/write"
PUBLISH = "Microsoft.Web/sites/publish/action"
HOST_KEY = "Microsoft.Web/sites/host/listkeys/action"
PLAN = f"{RG}/providers/Microsoft.Web/serverfarms/plan"
JOIN = "Microsoft.Web/serverfarms/join/action"
CONFIG = "Microsoft.Web/sites/config/write"
ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _result(*, site=APP, assignments=None, actions=None, site_inventory=True,
            identity=True, kind="app", extra=()):
    assignments = assignments if assignments is not None else [
        ("u-alice", "User", RG, ROLE_ID)]
    actions = actions if actions is not None else [ASSIGN, WRITE, PUBLISH]
    sites = ([{"id": APP, "type": "Microsoft.Web/sites", "kind": kind},
              {"id": OTHER, "type": "Microsoft.Web/sites", "kind": kind}]
             if site_inventory else [])
    graph = sites + ([UAMI] if identity else [])
    snap = az(assignments, roles={ROLE_ID: (actions, [])}, graph=graph,
              extra=[("app_service", SUB, sites, "collected" if site_inventory else "empty"),
                     ("managed_identity", SUB, [UAMI] if identity else [], "collected" if identity else "empty"),
                     *extra])
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)])


def test_exact_existing_app_and_operator_role_reaches_uami_conditionally():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_result(), "u-alice", TID) == {"mi-power": "conditional"}


def test_different_apps_cannot_combine_write_and_code_permission():
    roles = {ROLE_ID: ([ASSIGN, WRITE], []), "22222222-2222-2222-2222-222222222222": ([PUBLISH], [])}
    assignments = [("u-alice", "User", APP, ROLE_ID),
                   ("u-alice", "User", OTHER, "22222222-2222-2222-2222-222222222222"),
                   ("u-alice", "User", UAMI["id"], ROLE_ID)]
    snap = az(assignments, roles=roles, graph=[{"id": APP, "type": "Microsoft.Web/sites", "kind": "app"},
                                                {"id": OTHER, "type": "Microsoft.Web/sites", "kind": "app"}, UAMI],
              extra=[("app_service", SUB, [{"id": APP, "type": "Microsoft.Web/sites", "kind": "app"},
                                          {"id": OTHER, "type": "Microsoft.Web/sites", "kind": "app"}]),
                     ("managed_identity", SUB, [UAMI])])
    assert "mi-power" not in reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)]), "u-alice", TID)


def test_host_key_does_not_substitute_for_code_execution():
    assert "mi-power" not in reached(_result(actions=[ASSIGN, WRITE, HOST_KEY]), "u-alice", TID)


def test_function_code_write_does_not_count_on_ordinary_web_app():
    action = "Microsoft.Web/sites/functions/write"
    assert "mi-power" not in reached(_result(actions=[ASSIGN, WRITE, action]), "u-alice", TID)
    assert reached(_result(actions=[ASSIGN, WRITE, action], kind="functionapp"), "u-alice", TID) == {
        "mi-power": "conditional"}


def test_sitecontainer_write_is_bound_to_linux_app():
    action = "Microsoft.Web/sites/sitecontainers/write"
    assert "mi-power" not in reached(_result(actions=[ASSIGN, WRITE, action]), "u-alice", TID)
    assert reached(_result(actions=[ASSIGN, WRITE, action], kind="app,linux"), "u-alice", TID) == {
        "mi-power": "conditional"}


def test_onedeploy_route_remains_available_on_linux_app():
    action = "Microsoft.Web/sites/extensions/write"
    assert reached(_result(actions=[ASSIGN, WRITE, action], kind="app,linux"), "u-alice", TID) == {
        "mi-power": "conditional"}


def test_code_permission_at_exact_child_scope_is_kept():
    code_role = "22222222-2222-2222-2222-222222222222"
    app = {"id": APP, "type": "Microsoft.Web/sites", "kind": "app"}
    snap = az([("u-alice", "User", APP, ROLE_ID),
               ("u-alice", "User", UAMI["id"], ROLE_ID),
               ("u-alice", "User", APP + "/sourcecontrols/web", code_role)],
              roles={ROLE_ID: ([WRITE, ASSIGN], []),
                     code_role: (["Microsoft.Web/sites/sourcecontrols/write"], [])},
              graph=[app, UAMI], extra=[("app_service", SUB, [app]),
                                        ("managed_identity", SUB, [UAMI])])
    assert reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)]), "u-alice", TID) == {
        "mi-power": "conditional"}


def test_missing_site_or_assign_right_or_identity_has_no_named_edge():
    for result in (_result(site_inventory=False), _result(actions=[WRITE, PUBLISH]),
                   _result(identity=False)):
        assert "mi-power" not in reached(result, "u-alice", TID)


def test_new_app_path_requires_inventoried_group_and_joinable_plan():
    def run_new(actions, *, plan=True, group=True):
        extra = [("app_service", SUB, [], "empty"),
                 ("managed_identity", SUB, [UAMI]),
                 ("app_service_plan", SUB, [{"id": PLAN, "type": "Microsoft.Web/serverfarms"}] if plan else [],
                  "collected" if plan else "empty"),
                 ("resource_group", SUB, [{"id": RG}] if group else [],
                  "collected" if group else "empty")]
        snap = az([("u-alice", "User", RG, ROLE_ID)], roles={ROLE_ID: (actions, [])},
                  graph=[UAMI], extra=extra)
        return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)]), "u-alice", TID)

    assert run_new([ASSIGN, WRITE, CONFIG, JOIN]) == {"mi-power": "conditional"}
    for actions, plan, group in (([ASSIGN, WRITE, CONFIG], True, True),
                                 ([ASSIGN, WRITE, JOIN], True, True),
                                 ([ASSIGN, WRITE, CONFIG, JOIN], False, True),
                                 ([ASSIGN, WRITE, CONFIG, JOIN], True, False)):
        assert "mi-power" not in run_new(actions, plan=plan, group=group)
