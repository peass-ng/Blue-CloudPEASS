"""Focused privilege-path checks for Vertex AI and VM Migration."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from peaso.privesc.gcp_observed_impact import evidence_summary as observed_summary


def _migration_snapshot():
    host, target = "projects/host", "projects/target"
    email = "run@target.iam.gserviceaccount.com"
    resource = host + "/locations/us/sources/source/migratingVms/vm"
    role = host + "/roles/migrateOperator"
    rows = (
        ("project", host, [{"projectId": "host", "name": "projects/123"}]),
        ("project", target, [{"projectId": "target", "name": "projects/456"}]),
        ("service_account", target, [{"name": target + "/serviceAccounts/" + email, "email": email}]),
        ("vm_migration_target_project", host, [{"name": host + "/locations/global/targetProjects/target",
                                                "project": "target"}]),
        ("vm_migration_vm", host, [{"name": resource, "computeEngineTargetDefaults": {
            "targetProject": host + "/locations/global/targetProjects/target",
            "serviceAccount": email}}]),
        ("iam_role", host, [{"name": role, "includedPermissions": [
            "vmmigration.migratingVms.update", "vmmigration.cloneJobs.create"]}]),
        ("iam_policy", host, [{"name": host, "bindings": [
            {"role": role, "members": ["user:operator@example.com"]}]}]),
    )
    return {"provider": "gcp", "schema_version": 1, "scopes": [host, target], "metadata": {},
            "collections": [{"type": kind, "scope": scope, "status": "collected", "items": items}
                            for kind, scope, items in rows]}


def _migration_reaches(snapshot):
    model = GcpModel(snapshot)
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-vmmigration-migratingvm-metadata-clone")
    target = "serviceAccount:run@target.iam.gserviceaccount.com"
    return any(reach.source.id == "user:operator@example.com" and target in reach.targets
               for reach in Evaluator(model, [entry]).run())


def test_vm_migration_clones_only_configured_runtime_account():
    snap = _migration_snapshot()
    assert _migration_reaches(snap)
    target_project = next(c for c in snap["collections"]
                          if c["type"] == "vm_migration_target_project")["items"][0]
    target_project["project"] = "other"
    assert not _migration_reaches(snap)
    target_project["project"] = "target"
    next(c for c in snap["collections"] if c["type"] == "vm_migration_vm")[
        "items"][0]["computeEngineTargetDefaults"].pop("serviceAccount")
    assert not _migration_reaches(snap)
    next(c for c in snap["collections"] if c["type"] == "vm_migration_vm")[
        "items"][0]["computeEngineTargetDefaults"]["serviceAccount"] = "run@target.iam.gserviceaccount.com"
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["includedPermissions"].remove("vmmigration.cloneJobs.create")
    assert not _migration_reaches(snap)


def test_vm_migration_update_and_clone_must_cover_same_migrating_vm():
    snap = _migration_snapshot()
    model = GcpModel(snap)
    source = model.principals["user:operator@example.com"]
    target = model.sas["serviceAccount:run@target.iam.gserviceaccount.com"]
    original = model.check
    allowed = {
        "vmmigration.migratingVms.update": "/migratingVms/vm",
        "vmmigration.cloneJobs.create": "/migratingVms/other",
    }
    def split_check(principal, requirement, resource):
        action = requirement.get("action")
        if action in allowed:
            return original(principal, requirement, resource) if resource.endswith(allowed[action]) else None
        return original(principal, requirement, resource)
    model.check = split_check
    assert model.selector("gcp_vmmigration_metadata_clone_path", True,
                          {target.id: target}, source) == {}


def test_vertex_custom_identity_paths_require_create_and_target_actas():
    project = "projects/p1"
    email = "run@p1.iam.gserviceaccount.com"
    source = "user:operator@example.com"
    role = project + "/roles/vertexCreator"
    cases = (
        ("gcp-vertex-customjobs-create-actas", "aiplatform.customJobs.create"),
        ("gcp-vertex-customjobs-create-actas", "aiplatform.trainingPipelines.create"),
        ("gcp-vertex-pipelinejobs-create-actas", "aiplatform.pipelineJobs.create"),
        ("gcp-vertex-hptuningjobs-create-actas", "aiplatform.hyperparameterTuningJobs.create"),
        ("gcp-vertex-reasoningengines-create-actas", "aiplatform.reasoningEngines.create"),
        ("gcp-vertex-notebookexecutionjobs-create-actas", "aiplatform.notebookExecutionJobs.create"),
        ("gcp-vertex-workbench-instances-create-actas", "notebooks.instances.create"),
    )
    entries = {e["id"]: e for e in privesc.catalog()["entries"]}
    for technique, action in cases:
        account = {"name": project + "/serviceAccounts/" + email, "email": email,
                   "iamPolicy": {"bindings": [{"role": "roles/iam.serviceAccountUser",
                                               "members": [source]}]}}
        snap = {"provider": "gcp", "schema_version": 1, "scopes": [project], "metadata": {},
                "collections": [
                    {"type": "project", "scope": project, "status": "collected",
                     "items": [{"projectId": "p1", "name": "projects/123"}]},
                    {"type": "service_account", "scope": project, "status": "collected",
                     "items": [account]},
                    {"type": "iam_role", "scope": project, "status": "collected",
                     "items": [{"name": role, "includedPermissions": [action]}]},
                    {"type": "iam_policy", "scope": project, "status": "collected",
                     "items": [{"name": project, "bindings": [{"role": role, "members": [source]}]}]},
                ]}
        def reaches():
            model = GcpModel(snap)
            return any(reach.source.id == source and "serviceAccount:" + email in reach.targets
                       for reach in Evaluator(model, [entries[technique]]).run())
        assert reaches(), (technique, action, "positive")
        account["iamPolicy"]["bindings"] = []
        assert not reaches(), (technique, action, "no actAs")
        account["iamPolicy"]["bindings"] = [{"role": "roles/iam.serviceAccountUser",
                                              "members": [source]}]
        snap["collections"][2]["items"][0]["includedPermissions"] = []
        assert not reaches(), (technique, action, "no create")


def test_vmware_private_cloud_policy_self_grant_requires_exact_new_permission():
    from tests import test_peaso_privesc_gcp_resource_self_grant as template
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-vmwareengine-privateclouds-setiampolicy-private-cloud-self-grant")
    resource = "projects/p1/locations/us-central1-a/privateClouds/pc1"
    action = "vmwareengine.privateClouds.setIamPolicy"
    gained = "vmwareengine.privateClouds.showVcenterCredentials"
    record = {**template.proof(), "TechniqueId": entry["id"],
              "TargetResource": resource, "GrantedResource": resource,
              "AccessPermission": action, "GrantedPermissions": [gained]}
    def reaches(fact, permissions=(action,)):
        snap = template.case([fact] if fact else [], permissions=list(permissions))
        return template.paths(snap, entry)
    assert len(reaches(record)) == 1
    assert reaches(None) == {}
    assert reaches(record, permissions=()) == {}
    assert reaches({**record, "GrantedPermissions": ["vmwareengine.privateClouds.showNsxCredentials"]}) == {}


def test_vmware_generated_credentials_require_exact_plane_and_permission():
    from tests import test_peaso_privesc_gcp_external_principal as template
    entries = {e["id"]: e for e in privesc.catalog()["entries"]}
    for technique, plane, permission, subject in (
        ("gcp-vmwareengine-show-vcenter-credentials-external-principal",
         "vmware_vcenter", "vmwareengine.privateClouds.showVcenterCredentials", "CloudOwner@gve.local"),
        ("gcp-vmwareengine-show-nsx-credentials-external-principal",
         "vmware_nsx", "vmwareengine.privateClouds.showNsxCredentials", "admin"),
    ):
        service = template.RESOURCE + ("/vcenter" if plane == "vmware_vcenter" else "/nsx")
        record = {**template.proof(), "TechniqueId": technique, "TargetPlane": plane,
                  "AccessPermission": permission, "TargetServiceResource": service,
                  "TargetPrincipalId": subject, "ObservedPrincipalId": subject,
                  "PriorTestedResource": service, "AfterTestedResource": service}
        snap = template.case([record])
        role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
        role["includedPermissions"] = [permission]
        assert len(template.paths(snap, entries[technique])) == 1, technique
        record["TargetPlane"] = "vmware_nsx" if plane == "vmware_vcenter" else "vmware_vcenter"
        assert template.paths(snap, entries[technique]) == {}, (technique, "wrong plane")
        record["TargetPlane"] = plane
        role["includedPermissions"] = []
        assert template.paths(snap, entries[technique]) == {}, (technique, "missing permission")


def test_storage_composer_policy_paths_require_usable_environment():
    project, email = "projects/p0", "worker@p0.iam.gserviceaccount.com"
    source = "user:operator@example.com"
    bucket = "//storage.googleapis.com/projects/_/buckets/composer-bucket"
    folder = bucket + "/managedFolders/dags/"
    environment = {"name": project + "/locations/us-central1/environments/env",
                   "state": "RUNNING", "config": {"nodeConfig": {"serviceAccount": email},
                                                "dagGcsPrefix": "gs://composer-bucket/dags/"}}
    role = project + "/roles/storagePolicyWriter"
    snap = {"provider": "gcp", "schema_version": 1, "scopes": [project], "metadata": {},
            "collections": [
                {"type": "project", "scope": project, "status": "collected",
                 "items": [{"projectId": "p0", "name": "projects/100"}]},
                {"type": "service_account", "scope": project, "status": "collected",
                 "items": [{"email": email, "projectId": "p0"}]},
                {"type": "iam_role", "scope": project, "status": "collected",
                 "items": [{"name": role, "includedPermissions": [
                     "storage.buckets.setIamPolicy", "storage.managedFolders.setIamPolicy"]}]},
                {"type": "iam_policy", "scope": project, "status": "collected",
                 "items": [{"name": bucket, "project": project,
                            "bindings": [{"role": role, "members": [source]}]}]},
                {"type": "composer_environment", "scope": project, "status": "collected", "items": [environment]},
                {"type": "bucket", "scope": project, "status": "collected",
                 "items": [{"name": "composer-bucket", "iamConfiguration": {
                     "uniformBucketLevelAccess": {"enabled": True}}}]},
                {"type": "managed_folder", "scope": project, "status": "collected",
                 "items": [{"name": "dags/", "bucket": "composer-bucket", "project": project,
                            "resource": folder, "iamPolicy": {"bindings": [
                                {"role": role, "members": [source]}]},
                            "_coverage": {"iamPolicy": {"status": "collected"}}}]},
            ]}
    ids = ("gcp-storage-buckets-setiampolicy-composer",
           "gcp-storage-managedfolders-setiampolicy-composer")
    entries = [e for e in privesc.catalog()["entries"] if e["id"] in ids]
    def reached():
        model = GcpModel(snap)
        return {reach.entry["entry"]["id"] for reach in Evaluator(model, entries).run()
                if reach.source.id == source and
                "serviceAccount:" + email in reach.targets}
    assert reached() == set(ids)
    environment["state"] = "UPDATING"
    assert reached() == set(ids)
    environment["state"] = "ERROR"
    assert reached() == set()
    other_environment = {"name": project + "/locations/us-central1/environments/other",
                         "state": "RUNNING", "config": {"nodeConfig": {"serviceAccount": email},
                                                      "dagGcsPrefix": "gs://other-bucket/dags/"}}
    next(c for c in snap["collections"] if c["type"] == "composer_environment")[
        "items"].append(other_environment)
    assert reached() == set()  # policy rights on the ERROR environment's bucket do not cross over
    next(c for c in snap["collections"] if c["type"] == "composer_environment")[
        "items"].remove(other_environment)
    environment["state"] = "DELETING"
    assert reached() == set()
    environment.pop("state")
    assert reached() == set()


def test_storage_bucket_policy_code_consumer_joins_dataproc_init_bucket():
    project, email = "projects/p0", "worker@p0.iam.gserviceaccount.com"
    source = "user:operator@example.com"
    role = project + "/roles/storagePolicyWriter"
    bucket = "//storage.googleapis.com/projects/_/buckets/code-bucket"
    cluster = {"clusterName": "c", "_region": "us-central1",
               "config": {"gceClusterConfig": {"serviceAccount": email},
                          "initializationActions": [
                              {"executableFile": "gs://code-bucket/init/start.sh"}]}}
    snap = {"provider": "gcp", "schema_version": 1, "scopes": [project], "metadata": {},
            "collections": [
                {"type": "project", "scope": project, "status": "collected",
                 "items": [{"projectId": "p0", "name": "projects/100"}]},
                {"type": "service_account", "scope": project, "status": "collected",
                 "items": [{"email": email, "projectId": "p0"}]},
                {"type": "dataproc_cluster", "scope": project, "status": "collected", "items": [cluster]},
                {"type": "bucket", "scope": project, "status": "collected",
                 "items": [{"name": "code-bucket"}]},
                {"type": "iam_role", "scope": project, "status": "collected",
                 "items": [{"name": role, "includedPermissions": ["storage.buckets.setIamPolicy"]}]},
                {"type": "iam_policy", "scope": project, "status": "collected",
                 "items": [{"name": bucket, "project": project,
                            "bindings": [{"role": role, "members": [source]}]}]},
            ]}
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-storage-buckets-setiampolicy-code-consumers")
    def reaches():
        return any(reach.source.id == source and "serviceAccount:" + email in reach.targets
                   for reach in Evaluator(GcpModel(snap), [entry]).run())
    assert reaches()
    cluster["config"]["initializationActions"][0]["executableFile"] = "gs://other-bucket/init/start.sh"
    assert not reaches()


def test_vertex_and_vmware_observed_copy_names_the_setting_and_uncertainty():
    entries = [entry for entry in privesc.catalog()["entries"]
               if entry["id"].startswith(("gcp-vertex-", "gcp-vmmigration-", "gcp-vmwareengine-"))]
    assert len(entries) == 15
    for entry in entries:
        for status, confidence in (("FAIL", "derived"), ("MANUAL", "conditional"),
                                   ("UNKNOWN", "unknown")):
            unknown = status == "UNKNOWN"
            evidence = {
                "technique": {"id": entry["id"], "source": entry["source"]},
                "source": {"id": "user:bob@example.com", "label": "bob@example.com"},
                "targets": [{"id": "serviceAccount:worker@example.com",
                             "label": "worker@example.com", "underlying_count": 0 if unknown else 1}],
                "target_count": 0 if unknown else 1,
                "confidence": confidence, "conditions": [], "blockers_not_evaluated": [],
                "granting_statements": [] if unknown else [{"effect": "Allow"}],
            }
            rendered = observed_summary({"provider": "gcp", "check_id": entry["id"],
                                         "status": status, "evidence": evidence})
            assert rendered, (entry["id"], status)
            lines = rendered.splitlines()
            assert len(lines) == 3, (entry["id"], status)
            assert all(line.endswith(".") for line in lines)
            assert "alice" not in rendered.lower()
            assert "recorded grants may let" not in rendered
            if unknown:
                assert "unresolved" in lines[0]
