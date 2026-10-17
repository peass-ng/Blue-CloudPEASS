"""Small nonsecret Cloud Build trigger projection from an unmasked list response."""
from __future__ import annotations


def project_trigger(trigger):
    if not isinstance(trigger, dict):
        raise ValueError("Cloud Build trigger must be an object")
    output = {key: value for key, value in trigger.items() if key not in ("build", "substitutions")}
    if isinstance(trigger.get("substitutions"), dict):
        output["substitutionNames"] = sorted(trigger["substitutions"])
    if "build" in trigger:
        build = trigger["build"]
        if isinstance(build, dict):
            inline = {"serviceAccount": build.get("serviceAccount"),
                      "stepCount": len(build.get("steps") or [])}
            options = build.get("options")
            if "options" not in build or isinstance(options, dict) and "logging" not in options:
                inline["logging_field_state"] = "omitted"
            elif isinstance(options, dict) and isinstance(options.get("logging"), str):
                inline["logging_field_state"] = "present"
                inline["logging"] = options["logging"]
            else:
                inline["logging_field_state"] = "malformed"
            output["inlineBuild"] = inline
            steps = build.get("steps")
            if isinstance(steps, list) and all(isinstance(step, dict) and
                    isinstance(step.get("id"), str) and step["id"] for step in steps):
                output["buildDefinition"] = {"status": "collected",
                    "steps": [{"id": step["id"]} for step in steps]}
            else:
                output["buildDefinition"] = {"status": "unavailable", "steps": []}
        else:
            output["inlineBuild"] = {"logging_field_state": "malformed"}
            output["buildDefinition"] = {"status": "malformed", "steps": []}
    output["_representation"] = "full"
    return output
