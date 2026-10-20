"""Brief, non-secret observations for reviewed workload and RBAC findings."""
from .k8s_workload_clarity_reviewed import ROWS


def _text(value):
    return value if isinstance(value, str) and 0 < len(value) <= 160 and all(ord(c) >= 32 for c in value) else None


def _row(finding):
    if not isinstance(finding, dict) or finding.get("provider") != "k8s" or finding.get("status") != "FAIL":
        return None
    check_id = finding.get("check_id")
    return ROWS.get(check_id) if isinstance(check_id, str) else None


def workload_evidence_summary(finding):
    row = _row(finding)
    if row is None or not isinstance(finding.get("evidence"), dict):
        return None
    evidence = finding["evidence"]
    predicate = row["reviewed_binding"]["predicate"]
    if predicate == "runtime_default_seccomp":
        # This current source resolves overrides across regular/init/ephemeral rows.
        profiles, pod = evidence.get("container_profiles"), evidence.get("pod_profile")
        supported = (None, "RuntimeDefault", "Localhost", "Unconfined")
        if (not isinstance(profiles, list) or not profiles or pod not in supported
                or any(profile not in supported for profile in profiles)):
            return None
        effective = [profile if profile is not None else pod for profile in profiles]
        bad = next((profile for profile in effective if profile != "RuntimeDefault"), "no-failure")
        if bad == "no-failure":
            return None
        if bad is None:
            return "An assessed regular, init or ephemeral container has no declared or inherited RuntimeDefault seccomp profile."
        return "An assessed regular, init or ephemeral container declares or inherits " + bad + " seccomp instead of RuntimeDefault."
    if predicate == "effective_runtime_seccomp":
        failures = evidence.get("non_runtime_default")
        if isinstance(failures, list):
            for failure in failures[:100]:
                if not isinstance(failure, dict):
                    continue
                name, profile = _text(failure.get("container")), failure.get("effective_profile")
                if name and profile in ("Localhost", "Unconfined"):
                    return "Assessed Linux container “" + name + "” declares or inherits " + profile + " seccomp instead of RuntimeDefault."
        return None
    if finding["check_id"] == "k8s.claude.pod.no_host_ports":
        failures = evidence.get("violations")
        if isinstance(failures, list):
            for failure in failures[:100]:
                if not isinstance(failure, dict):
                    continue
                name, ports = _text(failure.get("container")), failure.get("host_ports")
                if (name and isinstance(ports, list) and ports
                        and all(type(port) is int and 1 <= port <= 65535 for port in ports)):
                    return "Regular container “" + name + "” declares hostPort " + str(ports[0]) + "."
        return None
    if row.get("static_observed_sentence"):
        return row["static_observed_sentence"]
    if predicate == "host_namespaces":
        names = [label for key, label in (("hostPID", "PID"), ("hostIPC", "IPC")) if evidence.get(key) is True]
        return "The PodSpec declares shared host " + " and ".join(names) + " namespaces." if names else None
    if predicate == "explicit_serviceaccount":
        if evidence.get("declared_service_account", object()) not in (None, ""):
            return None
        return "The PodSpec has no ServiceAccount name declared."
    if predicate == "no_literal_secret_env":
        values = evidence.get("literal_credential_env")
        if isinstance(values, list):
            for entry in values[:100]:
                if isinstance(entry, dict):
                    container, env = _text(entry.get("container")), _text(entry.get("env"))
                    if container and env:
                        return "Container “" + container + "” declares a nonempty literal in credential-like environment variable “" + env + "”."
        return None
    if predicate == "no_secret_env":
        values = evidence.get("violations")
        if isinstance(values, list):
            for entry in values[:100]:
                if not isinstance(entry, dict):
                    continue
                container, names = _text(entry.get("container")), entry.get("env")
                if container and isinstance(names, list) and names and _text(names[0]):
                    return "Container “" + container + "” loads environment variable “" + names[0] + "” from a Secret."
        return None
    observed_fields = row.get("evidence_presence_fields", [])
    if observed_fields and any(field in evidence for field in observed_fields):
        return "The resource " + row["observed_failure_phrase"] + "."
    if row["reviewed_binding"]["kind"] in ("role", "clusterrole"):
        values = evidence.get("matching_rules")
        if isinstance(values, list):
            for entry in values[:100]:
                if not isinstance(entry, dict):
                    continue
                verbs, resources = entry.get("verbs"), entry.get("resources")
                if isinstance(verbs, list) and verbs and isinstance(resources, list) and resources and _text(verbs[0]) and _text(resources[0]):
                    return "The role declares “" + verbs[0] + "” access to “" + resources[0] + "”."
        return None
    names = evidence.get("containers_needing_review")
    if names is None:
        names = evidence.get("privileged_containers")
    if names is None and isinstance(evidence.get("violations"), list):
        names = [entry.get("container") for entry in evidence["violations"] if isinstance(entry, dict)]
    if isinstance(names, list) and names and _text(names[0]):
        return "Container “" + names[0] + "” " + row["observed_failure_phrase"] + "."
    return None


def reviewed_workload_severity(finding):
    """Presentation risk for the specific failed configuration, not signed metadata."""
    row = _row(finding)
    return row["reviewed_severity"] if row is not None else None
