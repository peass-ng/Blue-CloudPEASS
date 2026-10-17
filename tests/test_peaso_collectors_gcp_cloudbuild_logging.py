"""Only the nonsecret logging enum survives Cloud Build trigger projection."""
import json

from peaso.collectors.gcp_cloudbuild_projection import project_trigger
from tests.test_peaso_collectors_gcp import collection, snapshot


def test_inline_logging_retained_without_build_code_or_substitution_values():
    trigger = {"id": "t1", "name": "push", "disabled": False,
               "substitutions": {"_TOKEN": "never-retain-token"},
               "build": {"serviceAccount": "builder@example.test", "steps": [
                   {"script": "never-retain-script", "args": ["never-retain-arg"]}],
                   "options": {"logging": "NONE", "env": ["never-retain-env"]}}}
    output = project_trigger(trigger)
    assert output["_representation"] == "full"
    assert output["inlineBuild"] == {"serviceAccount": "builder@example.test", "stepCount": 1,
                                     "logging_field_state": "present", "logging": "NONE"}
    assert output["substitutionNames"] == ["_TOKEN"]
    assert "never-retain" not in json.dumps(output)
    assert "build" not in output and "substitutions" not in output


def test_omitted_and_malformed_logging_shapes_are_distinct():
    base = {"id": "t1", "disabled": False}
    assert project_trigger({**base, "build": {"steps": []}})["inlineBuild"]["logging_field_state"] == "omitted"
    assert project_trigger({**base, "build": {"options": {}}})["inlineBuild"]["logging_field_state"] == "omitted"
    assert project_trigger({**base, "build": {"options": None}})["inlineBuild"]["logging_field_state"] == "malformed"
    assert project_trigger({**base, "build": {"options": {"logging": 7}}})["inlineBuild"]["logging_field_state"] == "malformed"
    assert project_trigger({**base, "build": "bad"})["inlineBuild"]["logging_field_state"] == "malformed"
    assert "inlineBuild" not in project_trigger({**base, "filename": "cloudbuild.yaml"})


def test_full_paginated_collector_preserves_only_logging_enum():
    def resolve(request):
        assert request["url"] == "https://cloudbuild.googleapis.com/v1/projects/p-one/locations/global/triggers"
        if request["params"].get("pageToken") == "next":
            return {"triggers": [{"id": "t2", "filename": "cloudbuild.yaml"}]}
        return {"nextPageToken": "next", "triggers": [{"id": "t1", "disabled": False,
                "build": {"steps": [{"script": "never-retain"}],
                          "options": {"logging": "NONE"}},
                "substitutions": {"_SECRET": "never-retain"}}]}
    result, transport = snapshot(["cloudbuild_trigger"], resolve, cloudbuild_locations=[])
    items = collection(result, "cloudbuild_trigger")["items"]
    assert transport.calls == 2 and len(items) == 2
    first = next(item for item in items if item["id"] == "t1")
    assert first["inlineBuild"]["logging"] == "NONE"
    assert first["_provenance"]["representation"] == "full"
    assert "never-retain" not in json.dumps(result)
