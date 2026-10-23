"""Job policy control must add a real execution route to the pinned identity."""

from peaso.privesc.effective_permissions.gcp import GcpModel

from test_peaso_privesc_audit_fixes import _GSA, _gcp_attached


PROJECT = "projects/p1"
SOURCE = "user:operator@example.com"
JOB = PROJECT + "/locations/us-central1/jobs/worker"
POLICY_ROLE = PROJECT + "/roles/jobPolicy"


def selected(*, command=None, act_as=False, existing=(), ready=True,
             policy_collected=True, boundary=False, constraints=False):
    bindings = [{"role": POLICY_ROLE, "members": [SOURCE]}]
    roles = [{"name": POLICY_ROLE, "includedPermissions": ["run.jobs.setIamPolicy"]}]
    for index, action in enumerate(existing):
        name = PROJECT + f"/roles/existing{index}"
        roles.append({"name": name, "includedPermissions": [action]})
        bindings.append({"role": name, "members": [SOURCE]})
    job = {"name": JOB, "template": {"template": {"serviceAccount": _GSA,
            "containers": [{"image": "example.invalid/job:1",
                            **({"command": command} if command is not None else {})}]}},
           "terminalCondition": {"state": "CONDITION_SUCCEEDED" if ready else "CONDITION_FAILED"},
           "reconciling": False, "iamPolicy": {"bindings": bindings},
           "_coverage": {"iamPolicy": {"status": "collected" if policy_collected else "denied"}}}
    builtin_roles = [
        {"name": "roles/run.jobsExecutorWithOverrides",
         "includedPermissions": ["run.jobs.run", "run.jobs.runWithOverrides"]},
        {"name": "roles/run.developer",
         "includedPermissions": ["run.jobs.update", "run.jobs.run"]},
    ]
    extra = [
        ("iam_role", PROJECT, roles, "collected"),
        ("iam_role_builtin", PROJECT, builtin_roles, "collected"),
        ("cloudrun_job", PROJECT, [job], "collected"),
        ("org_policy_effective", PROJECT,
         [{"constraint": "iam.allowedPolicyMemberDomains", "spec": {"rules": [{"allowAll": False}]}}]
         if constraints else [], "collected" if constraints else "empty"),
        ("policy_binding", PROJECT,
         [{"policyKind": "PRINCIPAL_ACCESS_BOUNDARY"}] if boundary else [],
         "collected" if boundary else "empty"),
        ("iam_deny_policy", PROJECT, [], "empty"),
    ]
    model, target = _gcp_attached(extra)
    if act_as or not policy_collected:
        project_policy = next(c for c in model.snapshot["collections"] if c["type"] == "iam_policy")
        project_policy["items"][0]["bindings"] = (
            ([{"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}] if act_as else [])
            + ([{"role": POLICY_ROLE, "members": [SOURCE]}] if not policy_collected else []))
        model = GcpModel(model.snapshot)
    return model.selector("gcp_run_job_policy_override_path", True,
                          {target.id: model.principals[target.id]}, model.principals[SOURCE])


def test_policy_self_grant_of_override_role_requires_injectable_command():
    target = "serviceAccount:" + _GSA
    assert selected(command=["/bin/sh"])[target] == (
        "conditional", "self_granted_cloud_run_job_override")
    assert selected(command=["/bin/curl"])[target][0] == "unknown"


def test_policy_self_grant_of_developer_role_requires_act_as():
    target = "serviceAccount:" + _GSA
    assert selected(command=["/bin/curl"], act_as=True)[target] == (
        "conditional", "self_granted_cloud_run_job_update_and_run")
    assert selected(command=["/bin/curl"], act_as=False)[target][0] == "unknown"


def test_policy_path_requires_new_job_action_and_current_policy_facts():
    target = "serviceAccount:" + _GSA
    assert selected(command=["/bin/sh"], existing=("run.jobs.run", "run.jobs.runWithOverrides")) == {}
    for options in ({"ready": False}, {"policy_collected": False},
                    {"boundary": True}, {"constraints": True}):
        assert selected(command=["/bin/sh"], **options)[target][0] == "unknown"
