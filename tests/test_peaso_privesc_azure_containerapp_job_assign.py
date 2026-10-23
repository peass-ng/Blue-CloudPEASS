"""Job UAMI assignment needs an exact writable and executable Job path."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-containerapp-job-assign-user-assigned-identity"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
JOB = RG + "/providers/Microsoft.App/jobs/work"
OTHER_JOB = RG + "/providers/Microsoft.App/jobs/other"
ENV = RG + "/providers/Microsoft.App/managedEnvironments/main"
OTHER_ENV = RG + "/providers/Microsoft.App/managedEnvironments/other"
UAI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"
WRITE = "Microsoft.App/jobs/write"
JOIN = "Microsoft.App/managedEnvironments/join/action"
ENV_WRITE = "Microsoft.App/managedEnvironments/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
WRITE_ROLE = "22222222-2222-2222-2222-222222222222"
JOIN_ROLE = "33333333-3333-3333-3333-333333333333"


def _run(*, existing=True, job_state="Succeeded", env_state="Succeeded", write_scope=None,
         join_scope=ENV, assign=True, env_write=False, job_status="collected",
         env_status="collected", group_status="collected", identity_status="collected"):
    write_scope = write_scope or (JOB if existing else RG)
    assignments = [("u-alice", "User", write_scope, WRITE_ROLE),
                   ("u-alice", "User", join_scope, JOIN_ROLE)]
    if assign:
        assignments.append(("u-alice", "User", UAI, ROLE_ID))
    if env_write:
        assignments.append(("u-alice", "User", RG, "44444444-4444-4444-4444-444444444444"))
    roles = {ROLE_ID: ([ASSIGN], []), WRITE_ROLE: ([WRITE], []), JOIN_ROLE: ([JOIN], []),
             "44444444-4444-4444-4444-444444444444": ([ENV_WRITE], [])}
    job = {"id": JOB, "type": "Microsoft.App/jobs", "location": "eastus",
           "properties": {"provisioningState": job_state, "environmentId": ENV}}
    env = {"id": ENV, "type": "Microsoft.App/managedEnvironments", "location": "eastus",
           "properties": {"provisioningState": env_state}}
    identity = {"id": UAI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                "properties": {"principalId": "mi-worker", "clientId": "worker-client"}}
    extra = [("container_app_job", SUB, [job] if existing and job_status == "collected" else [],
              job_status if existing else "empty" if job_status == "collected" else job_status),
             ("container_app_environment", SUB, [env] if env_status == "collected" else [], env_status),
             ("resource_group", SUB, [{"id": RG}] if group_status == "collected" else [], group_status),
             ("managed_identity", SUB, [identity] if identity_status == "collected" else [], identity_status)]
    snap = az(assignments, roles=roles, extra=extra)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_existing_job_write_and_assignment_reaches_verified_identity():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(), "u-alice", TID) == {"mi-worker": "conditional"}
    # Updating the existing Job does not need a new environment join.
    assert reached(_run(join_scope=OTHER_ENV), "u-alice", TID) == {"mi-worker": "conditional"}


def test_new_job_requires_exact_joinable_environment():
    assert reached(_run(existing=False), "u-alice", TID) == {"mi-worker": "conditional"}
    assert reached(_run(existing=False, join_scope=OTHER_ENV), "u-alice", TID) == {}
    assert reached(_run(existing=False, env_state="Failed"), "u-alice", TID) == {}
    assert reached(_run(existing=False, env_status="empty", env_write=True, join_scope=RG), "u-alice", TID) == {
        "mi-worker": "conditional"}


def test_unrelated_write_and_missing_assignment_do_not_form_a_path():
    assert reached(_run(write_scope=OTHER_JOB), "u-alice", TID) == {}
    assert reached(_run(assign=False), "u-alice", TID) == {}
    assert set(reached(_run(job_state=None), "u-alice", TID).values()) == {"unknown"}


def test_incomplete_job_environment_group_or_identity_inventory_is_unresolved():
    for case in ({"job_status": "denied"}, {"env_status": "denied"},
                 {"group_status": "denied", "existing": False},
                 {"identity_status": "denied"}):
        result = reached(_run(**case), "u-alice", TID)
        assert result and set(result.values()) == {"unknown"}


def test_native_job_projection_excludes_template_and_rejects_foreign_resource():
    path = Path(__file__).resolve().parents[1] / "peaso/collectors/azure_containerapp_jobs.py"
    spec = importlib.util.spec_from_file_location("azure_containerapp_jobs_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw = {"id": JOB, "type": "Microsoft.App/jobs", "location": "eastus",
           "properties": {"provisioningState": "Succeeded", "environmentId": ENV,
                          "template": {"containers": [{"env": [{"name": "SECRET", "value": "private"}]}]}}}
    projected = module._project(raw, JOB, module.JOB_KIND)
    assert "private" not in repr(projected)
    assert projected["properties"]["environmentId"] == ENV
    with pytest.raises(ValueError):
        module._project({**raw, "id": OTHER_JOB}, JOB, module.JOB_KIND)


def test_native_job_and_environment_collection_reads_exact_resources():
    path = Path(__file__).resolve().parents[1] / "peaso/collectors/azure_containerapp_jobs.py"
    spec = importlib.util.spec_from_file_location("azure_containerapp_jobs_collect_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    objects = {
        JOB: {"id": JOB, "type": "Microsoft.App/jobs", "location": "eastus",
              "properties": {"provisioningState": "Succeeded", "environmentId": ENV,
                             "template": {"secret": "private"}}},
        ENV: {"id": ENV, "type": "Microsoft.App/managedEnvironments", "location": "eastus",
              "properties": {"provisioningState": "Succeeded"}},
    }
    calls = []

    class Reader:
        def __init__(self):
            self.collections = []

        def pages(self, request, url):
            calls.append(url)
            if "/providers/Microsoft.App/jobs?" in url:
                yield [{"id": JOB, "type": "Microsoft.App/jobs"}]
            elif "/providers/Microsoft.App/managedEnvironments?" in url:
                yield [{"id": ENV, "type": "Microsoft.App/managedEnvironments"}]
            else:
                raise AssertionError(url)

        def call(self, request, url):
            calls.append(url)
            return objects[url.removeprefix(module.ARM).split("?", 1)[0]]

        def run(self, jobs):
            for kind, scope, _, fetch in jobs:
                rows = [row for page in fetch() for row in page]
                self.collections.append({"type": kind, "scope": scope,
                                         "status": "collected" if rows else "empty", "items": rows})

    reader = Reader()
    module.collect(reader, None, [SUB], set(module.NATIVE_TYPES))
    assert len(calls) == 4
    assert {c["type"] for c in reader.collections} == set(module.NATIVE_TYPES)
    assert "private" not in repr(reader.collections)
