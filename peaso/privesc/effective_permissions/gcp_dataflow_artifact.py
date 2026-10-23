"""Join an active Dataflow worker to one mutable, readable code object."""

from __future__ import annotations

from datetime import datetime, timezone

from . import inventory_status, items


def _unlocked(metadata):
    if not isinstance(metadata, dict) or not str(metadata.get("generation") or "").isdigit():
        return None
    if metadata.get("temporaryHold") is True or metadata.get("eventBasedHold") is True:
        return False
    for key in ("retentionExpirationTime", "retainUntilTime"):
        value = metadata.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            return None
        try:
            deadline = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if deadline.tzinfo is None:
            return None
        if deadline > datetime.now(timezone.utc):
            return False
    return True


def _object_resource(model, bucket, name):
    project = model.bucket_projects.get(bucket)
    if not project:
        return None
    root = f"//storage.googleapis.com/projects/_/buckets/{bucket}"
    resource = root + "/objects/" + name
    parent = root
    if model.bucket_ubla.get(bucket):
        folders = [(len(folder), path) for folder, path in model.managed_folders.get(bucket, ())
                   if name.startswith(folder)]
        if folders:
            parent = max(folders)[1]
    model.parents.setdefault(resource, parent)
    return resource


def select(model, candidates, source):
    if source is None:
        return {}
    job_status = {model._norm_scope(scope): state for scope, state in
                  inventory_status(model.snapshot, "dataflow_privesc_job").items()}
    pipeline_status = {model._norm_scope(scope): state for scope, state in
                       inventory_status(model.snapshot, "dataflow_privesc_pipeline").items()}
    jobs = {}
    for scope, row in items(model.snapshot, "dataflow_privesc_job"):
        project = model._norm_scope(scope)
        if row.get("projectId") != project.split("/", 1)[-1]:
            continue
        email = row.get("workerServiceAccountEmail")
        if isinstance(email, str):
            jobs.setdefault(email.lower(), []).append((project, row))
    pipelines = []
    for scope, row in items(model.snapshot, "dataflow_privesc_pipeline"):
        project = model._norm_scope(scope)
        if row.get("projectId") == project.split("/", 1)[-1]:
            pipelines.append((project, row))
    out = {}
    for tid, target in candidates.items():
        email = str(target.attrs.get("email") or "").lower()
        uncertain = False
        for project, pipeline in pipelines:
            worker = pipeline.get("workerServiceAccountEmail")
            if worker is not None and str(worker).lower() != email:
                continue
            ref = pipeline.get("templateObject")
            if not isinstance(ref, dict):
                uncertain = True
                continue
            bucket, name = ref.get("bucket"), ref.get("object")
            if not isinstance(bucket, str) or not isinstance(name, str):
                uncertain = True
                continue
            resource = _object_resource(model, bucket, name)
            if resource is None:
                uncertain = True
                continue
            rights = [model.check(source, {"action": action}, resource)
                      for action in ("storage.objects.create", "storage.objects.delete")]
            if all(right is not None for right in rights):
                # The list response does not establish the template reader or
                # whether modified template contents would execute as this worker.
                uncertain = True
        for job_project, job in jobs.get(email, ()):
            if job_status.get(job_project) not in ("collected", "empty"):
                uncertain = True
                continue
            if (job.get("_representation") != "privesc_code_references"
                    or job.get("currentState") != "JOB_STATE_RUNNING"):
                uncertain = True
                continue
            references = job.get("codeObjects")
            if not isinstance(references, list):
                uncertain = True
                continue
            if not references or all(isinstance(ref, dict) and ref.get("sha256") for ref in references):
                uncertain = True
            for artifact in references:
                if not isinstance(artifact, dict) or artifact.get("kind") not in ("worker_package", "udf_or_yaml"):
                    uncertain = True
                    continue
                if artifact.get("sha256"):
                    continue
                bucket, name = artifact.get("bucket"), artifact.get("object")
                if not isinstance(bucket, str) or not isinstance(name, str):
                    uncertain = True
                    continue
                if artifact.get("metadataStatus") != "collected":
                    uncertain = True
                    continue
                unlocked = _unlocked(artifact.get("metadata"))
                if unlocked is not True:
                    uncertain |= unlocked is None
                    if unlocked is False and _object_resource(model, bucket, name):
                        resource = _object_resource(model, bucket, name)
                        uncertain |= any(model.check(source, {"action": action}, resource) is not None
                                         for action in ("storage.objects.update", "storage.objects.overrideUnlockedRetention"))
                    continue
                object_resource = _object_resource(model, bucket, name)
                if not object_resource:
                    uncertain = True
                    continue
                grants = [model.check(source, {"action": action}, object_resource)
                          for action in ("storage.objects.create", "storage.objects.delete")]
                grants.append(model.check(target, {"action": "storage.objects.get"}, object_resource))
                if all(grant is not None and grant.confidence == "derived" for grant in grants):
                    out[tid] = ("conditional", "active_dataflow_worker_reads_mutable_code_object")
                    break
                if any(grant is not None for grant in grants):
                    uncertain = True
            if tid in out:
                break
        if tid not in out:
            if uncertain:
                out[tid] = ("unknown", "dataflow_code_object_or_runtime_unresolved")
            elif any(pipeline_status.get(project) not in ("collected", "empty")
                     for project in model.scopes if str(project).startswith("projects/")):
                out[tid] = ("unknown", "dataflow_scheduled_pipeline_inventory_unresolved")
            elif any(job_status.get(project) not in ("collected", "empty")
                     for project in model.scopes if str(project).startswith("projects/")):
                out[tid] = ("unknown", "dataflow_active_job_inventory_unresolved")
    return out
