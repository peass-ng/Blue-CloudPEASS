"""Job template override reaches only identities usable on that exact Job."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-containerapp-job-start-template-override"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
JOB = RG + "/providers/Microsoft.App/jobs/work"
OTHER = RG + "/providers/Microsoft.App/jobs/other"
ENV = RG + "/providers/Microsoft.App/managedEnvironments/main"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
START = "Microsoft.App/jobs/start/action"
WRITE = "Microsoft.App/jobs/write"


def _job(*, lifecycle=None, principal="mi-job", uai=False, state="Succeeded", env=ENV,
         workload_profile=None):
    identity = ({"type": "UserAssigned", "userAssignedIdentities": {UAI: {"principalId": principal}}}
                if uai else {"type": "SystemAssigned", "principalId": principal})
    settings = None if lifecycle is None else [{"identity": UAI if uai else "system",
                                                "lifecycle": lifecycle}]
    props = {"provisioningState": state, "environmentId": env,
             "configuration": {"identitySettings": settings}}
    if workload_profile is not None:
        props["workloadProfileName"] = workload_profile
    return {"id": JOB, "type": "Microsoft.App/jobs", "location": "eastus", "identity": identity,
            "properties": props}


def _run(*, job=None, job_status="collected", env_status="collected",
         env_state="Succeeded", env_profiles=None, actions=(START,), permission_scope=JOB, graph=None):
    job = job or _job()
    env = {"id": ENV, "type": "Microsoft.App/managedEnvironments", "location": "eastus",
           "properties": {"provisioningState": env_state}}
    if env_profiles is not None:
        env["properties"]["workloadProfiles"] = env_profiles
    extra = [("container_app_job", SUB, [job] if job_status == "collected" else [], job_status),
             ("container_app_environment", SUB, [env] if env_status == "collected" else [], env_status)]
    snap = az([("u-alice", "User", permission_scope, ROLE_ID)],
              roles={ROLE_ID: (list(actions), [])}, graph=graph or [], extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_start_override_reaches_current_system_and_user_assigned_identity():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-job": "conditional"}
    assert reached(_run(job=_job(uai=True, principal="mi-worker")), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_start_respects_lifecycle_and_write_can_change_it():
    assert reached(_run(job=_job(lifecycle="Main")), "u-alice", TID) == {"mi-job": "conditional"}
    assert reached(_run(job=_job(lifecycle="None")), "u-alice", TID) == {}
    assert set(reached(_run(job=_job(lifecycle="Init")), "u-alice", TID).values()) == {
        "unknown"}
    assert reached(_run(job=_job(lifecycle="None"), actions=(WRITE,)), "u-alice", TID) == {
        "mi-job": "conditional"}


def test_init_stage_requires_confirmed_consumption_workload_profile():
    init = _job(lifecycle="Init", workload_profile="consumption")
    consumption = [{"name": "consumption", "workloadProfileType": "Consumption"}]
    dedicated = [{"name": "consumption", "workloadProfileType": "GeneralPurpose"}]
    assert reached(_run(job=init, env_profiles=consumption), "u-alice", TID) == {
        "mi-job": "conditional"}
    assert reached(_run(job=init, env_profiles=dedicated), "u-alice", TID) == {}
    assert set(reached(_run(job=init, env_profiles=[{
        "name": "consumption", "workloadProfileType": "FutureProfile"}]),
        "u-alice", TID).values()) == {"unknown"}
    assert set(reached(_run(job=init), "u-alice", TID).values()) == {"unknown"}


def test_wrong_job_no_permission_or_unusable_environment_is_excluded():
    assert reached(_run(permission_scope=OTHER), "u-alice", TID) == {}
    assert reached(_run(actions=()), "u-alice", TID) == {}
    assert reached(_run(env_state="Failed"), "u-alice", TID) == {}
    assert reached(_run(job=_job(state="Failed")), "u-alice", TID) == {}


def test_stale_graph_identity_does_not_replace_current_native_identity():
    graph = [{"id": JOB, "type": "Microsoft.App/jobs", "identity": {
        "type": "SystemAssigned", "principalId": "mi-old"}, "properties": {}}]
    assert reached(_run(job=_job(principal="mi-current"), graph=graph), "u-alice", TID) == {
        "mi-current": "conditional"}


def test_missing_job_environment_or_identity_detail_is_unresolved():
    for case in ({"job_status": "denied"}, {"env_status": "denied"},
                 {"job": _job(state=None)}, {"job": _job(lifecycle="Other")}):
        result = reached(_run(**case), "u-alice", TID)
        assert result and set(result.values()) == {"unknown"}


def test_native_job_projection_retains_identity_settings_without_secrets():
    path = Path(__file__).resolve().parents[1] / "peaso/collectors/azure_containerapp_jobs.py"
    spec = importlib.util.spec_from_file_location("azure_containerapp_job_start_projection", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw = _job(lifecycle="Main", uai=True, principal="mi-worker")
    raw["properties"]["template"] = {"containers": [{"env": [{"name": "SECRET", "value": "private"}]}]}
    projected = module._project(raw, JOB, module.JOB_KIND)
    assert projected["identity"]["userAssignedIdentities"][UAI]["principalId"] == "mi-worker"
    assert projected["properties"]["configuration"]["identitySettings"][0]["lifecycle"] == "Main"
    assert "private" not in repr(projected)
    environment = {"id": ENV, "type": "Microsoft.App/managedEnvironments", "location": "eastus",
                   "properties": {"provisioningState": "Succeeded", "workloadProfiles": [
                       {"name": "consumption", "workloadProfileType": "Consumption"}]}}
    projected_environment = module._project(environment, ENV, module.ENV_KIND)
    assert projected_environment["properties"]["workloadProfiles"] == [
        {"name": "consumption", "workloadProfileType": "Consumption"}]
