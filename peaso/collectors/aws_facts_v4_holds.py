"""Private, read-only metadata for two v4 AWS holds.

No source-principal authorization, execution, control or attestation is inferred.
All requests use the scan's shared scheduler and its pagination, retry and
cancellation limits. The GetPipeline response is projected before caching.
"""
from __future__ import annotations

import copy
import re


SPECS = {
    "ec2_instance_profile_association": (
        "ec2", "describe_iam_instance_profile_associations", "IamInstanceProfileAssociations"),
}
NATIVE_IDS = {"ec2_instance_profile_association": "AssociationId"}
READ_ACTIONS = {("codepipeline", "get_pipeline")}

_PIPELINE_NAME = re.compile(r"[A-Za-z0-9.@_-]{1,100}")
_REPOSITORY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_BRANCH_NAME = re.compile(r"[A-Za-z0-9._/-]{1,256}")
_PROJECT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{1,254}")
_ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn):([a-z0-9-]+):([a-z0-9-]*):([0-9]{12}):(.+)")


def _arn(value, service=None, account=None, region=None):
    match = _ARN.fullmatch(value) if isinstance(value, str) else None
    return bool(match and (service is None or match[2] == service)
                and (account is None or match[4] == account)
                and (region is None or match[3] == region))


def _status(value):
    return value.get("collection_status") if isinstance(value, dict) else None


def project_pipeline_response(response):
    """Discard arbitrary CodePipeline configuration before Requests caches it."""
    from .aws import ReadFailure
    pipeline = response.get("pipeline") if isinstance(response, dict) else None
    if not isinstance(pipeline, dict) or not isinstance(pipeline.get("stages"), list):
        raise ReadFailure("malformed", "malformed_pipeline")
    stages = []
    for stage in pipeline["stages"]:
        if not isinstance(stage, dict) or not isinstance(stage.get("actions"), list):
            raise ReadFailure("malformed", "malformed_pipeline_stage")
        actions = []
        for action in stage["actions"]:
            if not isinstance(action, dict):
                raise ReadFailure("malformed", "malformed_pipeline_action")
            kind = action.get("actionTypeId") or {}
            if not isinstance(kind, dict):
                raise ReadFailure("malformed", "malformed_pipeline_action")
            provider = kind.get("provider")
            category = kind.get("category")
            if kind.get("owner") != "AWS" or (category, provider) not in {
                ("Source", "CodeCommit"), ("Build", "CodeBuild")}:
                continue
            config = action.get("configuration") or {}
            if not isinstance(config, dict):
                raise ReadFailure("malformed", "malformed_pipeline_action")
            keys = ("RepositoryName", "BranchName", "OutputArtifactFormat") if provider == "CodeCommit" else (
                "ProjectName", "PrimarySource", "ServiceRoleArnOverride")
            artifacts = {}
            for field in ("inputArtifacts", "outputArtifacts"):
                values = action.get(field) or []
                if not isinstance(values, list):
                    raise ReadFailure("malformed", "malformed_pipeline_artifacts")
                artifacts[field] = [{"name": item.get("name")} for item in values if isinstance(item, dict)]
            actions.append({"name": action.get("name"), "category": category, "provider": provider,
                            "region": action.get("region"), "runOrder": action.get("runOrder"),
                            "configuration": {key: config.get(key) for key in keys}, **artifacts})
        stages.append({"name": stage.get("name"), "actions": actions})
    return {"pipeline": {"name": pipeline.get("name"), "stages": stages}}


def enrich_pipelines(requests, session, region, items):
    output = []
    for raw in items:
        item = copy.deepcopy(raw)
        name = item.get("name")
        if isinstance(name, str) and _PIPELINE_NAME.fullmatch(name):
            item["ActionMetadata"] = requests.detail(
                session, "codepipeline", region, "get_pipeline", name=name)
        else:
            item["ActionMetadata"] = {"collection_status": "malformed", "error": {"code": "malformed_pipeline_name"}}
        output.append(item)
    return output


ENRICHERS = {"codepipeline_pipeline": enrich_pipelines}


def _collection(snapshot, kind, scope):
    rows = [row for row in snapshot.get("collections", [])
            if isinstance(row, dict) and row.get("type") == kind and row.get("scope") == scope]
    return rows[0] if len(rows) == 1 else None


def _items(collection):
    return collection.get("items", []) if isinstance(collection, dict) and isinstance(collection.get("items"), list) else []


def codecommit_build_links(snapshot, account, region, *, partition="aws"):
    """Return configured direct source-artifact/build-role joins, never authority."""
    scope = f"{account}/{region}"
    pipelines = _collection(snapshot, "codepipeline_pipeline", scope)
    projects = _collection(snapshot, "codebuild_project", scope)
    status = {"Pipelines": pipelines.get("status") if pipelines else "not_collected",
              "Projects": projects.get("status") if projects else "not_collected"}
    links = []
    for pipeline in _items(pipelines):
        detail = pipeline.get("ActionMetadata")
        if _status(detail) != "collected":
            continue
        metadata = detail.get("pipeline") or {}
        name = pipeline.get("name")
        if name != metadata.get("name") or not isinstance(name, str) or not _PIPELINE_NAME.fullmatch(name):
            continue
        pipeline_arn = f"arn:{partition}:codepipeline:{region}:{account}:{name}"
        stages = metadata.get("stages") or []
        sources, builds = [], []
        for stage_index, stage in enumerate(stages):
            for action in stage.get("actions") or []:
                if action.get("region") not in (None, region):
                    continue  # Cross-Region action inventory must be joined separately.
                provider = action.get("provider")
                config = action.get("configuration") or {}
                if provider == "CodeCommit" and action.get("category") == "Source":
                    repository, branch = config.get("RepositoryName"), config.get("BranchName")
                    if not (isinstance(repository, str) and _REPOSITORY_NAME.fullmatch(repository)
                            and isinstance(branch, str) and _BRANCH_NAME.fullmatch(branch)):
                        continue
                    sources.append((stage_index, action, repository, branch))
                if provider == "CodeBuild" and action.get("category") == "Build":
                    builds.append((stage_index, action))
        for source_index, source, repository, branch in sources:
            for build_index, build in builds:
                if build_index <= source_index:
                    continue
                output_names = {v.get("name") for v in source.get("outputArtifacts") or []
                                if isinstance(v, dict) and isinstance(v.get("name"), str)}
                input_names = {v.get("name") for v in build.get("inputArtifacts") or []
                               if isinstance(v, dict) and isinstance(v.get("name"), str)}
                for artifact in sorted((output_names & input_names) - {None, ""}):
                    project_name = (build.get("configuration") or {}).get("ProjectName")
                    if not isinstance(project_name, str) or not _PROJECT_NAME.fullmatch(project_name):
                        continue
                    project_rows = [p for p in _items(projects) if p.get("name") == project_name]
                    project = project_rows[0] if len(project_rows) == 1 else None
                    config = project.get("Configuration") if project else None
                    definitions = config.get("projects") if _status(config) == "collected" else None
                    definition = definitions[0] if isinstance(definitions, list) and len(definitions) == 1 else None
                    if not isinstance(definition, dict) or definition.get("name") != project_name:
                        definition = None
                    project_arn = definition.get("arn") if definition else None
                    if not _arn(project_arn, "codebuild", account, region) or not project_arn.startswith(f"arn:{partition}:"):
                        definition = None
                    override = (build.get("configuration") or {}).get("ServiceRoleArnOverride")
                    role = (override or definition.get("serviceRole")) if definition else None
                    role_valid = (bool(definition) and _arn(role, "iam", account, "")
                                  and role.startswith(f"arn:{partition}:") and ":role/" in role)
                    links.append({
                        "Status": "configured" if definition and role_valid else "partial",
                        "RepositoryArn": f"arn:{partition}:codecommit:{region}:{account}:{repository}",
                        "RepositoryName": repository, "Branch": branch,
                        "PipelineArn": pipeline_arn, "SourceAction": source.get("name"),
                        "SourceOutputArtifact": artifact, "BuildAction": build.get("name"),
                        "BuildInputArtifact": artifact,
                        "BuildProjectArn": project_arn if definition else None,
                        "BuildRoleArn": role if role_valid else None,
                        "BuildRoleOrigin": ("action_override" if override else "project_default") if role_valid else None,
                        "PrimarySource": (build.get("configuration") or {}).get("PrimarySource"),
                        "SourceProvider": "CodeCommit", "BuildProvider": "CodeBuild",
                        "RepositoryExists": None, "BranchWritable": None,
                        "BuildSpecUsesInput": None, "ExecutionPathAvailable": None,
                        "VerifiedPreconditions": None})
    return {"status": status, "links": links}


def ec2_profile_state(snapshot, account, region, *, partition="aws"):
    """Join current association state, instance metadata and IAM profile roles."""
    scope = f"{account}/{region}"
    instances = _collection(snapshot, "instance", scope)
    associations = _collection(snapshot, "ec2_instance_profile_association", scope)
    roles = _collection(snapshot, "iam_role", f"{account}/global")
    status = {"Instances": instances.get("status") if instances else "not_collected",
              "Associations": associations.get("status") if associations else "not_collected",
              "Roles": roles.get("status") if roles else "not_collected"}
    role_profiles = {}
    for role in _items(roles):
        role_arn = role.get("Arn")
        if not (_arn(role_arn, "iam", account, "") and ":role/" in role_arn):
            continue
        for profile in role.get("InstanceProfileList") or []:
            profile_arn = profile.get("Arn") if isinstance(profile, dict) else None
            if _arn(profile_arn, "iam", account, "") and ":instance-profile/" in profile_arn:
                role_profiles.setdefault(profile_arn, set()).add(role_arn)
    by_instance = {}
    for association in _items(associations):
        if isinstance(association, dict) and isinstance(association.get("InstanceId"), str):
            by_instance.setdefault(association["InstanceId"], []).append(association)
    rows = []
    for instance in _items(instances):
        ident = instance.get("InstanceId")
        if not isinstance(ident, str) or not re.fullmatch(r"i-[0-9a-f]{8,17}", ident):
            continue
        matches = by_instance.get(ident, [])
        profile = instance.get("IamInstanceProfile") or {}
        instance_profile = profile.get("Arn") if isinstance(profile, dict) else None
        current_state = "unknown"
        association = matches[0] if len(matches) == 1 else None
        if status["Instances"] in ("collected", "empty") and status["Associations"] in ("collected", "empty"):
            if not matches and not instance_profile:
                current_state = "absent"
            elif association and association.get("State") == "associated":
                assoc_profile = association.get("IamInstanceProfile") or {}
                assoc_arn = assoc_profile.get("Arn") if isinstance(assoc_profile, dict) else None
                if assoc_arn == instance_profile and _arn(assoc_arn, "iam", account, ""):
                    current_state = "present"
        current_profile = instance_profile if current_state == "present" else None
        rows.append({"InstanceArn": f"arn:{partition}:ec2:{region}:{account}:instance/{ident}",
                     "InstanceId": ident, "InstanceState": (instance.get("State") or {}).get("Name"),
                     "CurrentProfileState": current_state,
                     "CurrentProfileArn": current_profile,
                     "AssociationId": association.get("AssociationId") if current_state == "present" else None,
                     "CurrentProfileRoleArns": sorted(role_profiles.get(current_profile, ())) if status["Roles"] == "collected" else [],
                     "InstanceControlled": None, "AssociationAction": None,
                     "VerifiedPreconditions": None})
    return {"status": status, "instances": rows, "role_profiles": {k: sorted(v) for k, v in role_profiles.items()}}


def _unique_profile_metadata(rows, identity):
    """Contradictory duplicate native rows must not become first-row evidence."""
    from .aws import ReadFailure
    seen = {}
    for row in rows:
        key = row.get(identity) if isinstance(row, dict) else None
        if not isinstance(key, str) or not key:
            raise ReadFailure('malformed', 'instance_profile_native_identity_invalid')
        if key in seen and seen[key] != row:
            raise ReadFailure('malformed', 'instance_profile_native_identity_conflict')
        seen[key] = row
    return rows


def profile_associations(requests, session, region, account):
    from .aws import ReadFailure, ReadResult
    read = requests.pages(session, 'ec2', region, 'describe_iam_instance_profile_associations', 'IamInstanceProfileAssociations')
    try:
        _unique_profile_metadata(read.items, 'AssociationId')
    except ReadFailure as exc:
        return ReadResult([], exc.status, {'code': exc.code})
    return read


def unique_instances(requests, session, region, rows):
    return _unique_profile_metadata(rows, 'InstanceId')


FETCHERS = {'ec2_instance_profile_association': profile_associations}
ENRICHERS['instance'] = unique_instances
