"""Run baked-in Powerpipe benchmarks with an isolated Steampipe database."""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
from query_context import prepare_query_context


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["aws", "azure", "gcp", "kubernetes"])
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--input-dir", default="/input")
    parser.add_argument("--output-dir", default="/output")
    parser.add_argument("--work-dir", help="Private runtime directory managed by the caller (native workers).")
    args = parser.parse_args()
    if not args.provider and not args.self_test:
        parser.error("--provider is required")
    output = pathlib.Path(args.output_dir)
    auth = pathlib.Path(args.input_dir)
    os.environ["BLUEPEASS_AUTH_DIR"] = str(auth)
    output.mkdir(exist_ok=True)
    result = {"runs": [], "excluded_controls": [], "errors": [], "query_context": []}
    runtime = pathlib.Path(args.work_dir) if args.work_dir else pathlib.Path(tempfile.mkdtemp(prefix="bluepeass-"))
    runtime.mkdir(mode=0o700, exist_ok=True)
    os.environ["USER"] = "bluepeass"
    os.environ["PIPES_INSTALL_DIR"] = str(runtime / "pipes")
    # Docker runs as the host UID so private bind mounts remain private. Give
    # PostgreSQL libc a passwd entry for arbitrary host UIDs without root.
    libraries = list(pathlib.Path("/usr/lib").glob("*/libnss_wrapper.so"))
    if libraries:
        (runtime / "passwd").write_text(f"bluepeass:x:{os.getuid()}:{os.getgid()}:BluePEASS:{runtime}:/bin/sh\n")
        (runtime / "group").write_text(f"bluepeass:x:{os.getgid()}:\n")
        os.environ.update(LD_PRELOAD=str(libraries[0]), NSS_WRAPPER_PASSWD=str(runtime / "passwd"), NSS_WRAPPER_GROUP=str(runtime / "group"))
    os.environ["POWERPIPE_INSTALL_DIR"] = str(runtime / "powerpipe")
    install = runtime / ".steampipe"
    shutil.copytree("/opt/steampipe", install)
    for path in (install / "config").glob("*.spc"):
        path.unlink()
    if not args.self_test:
        for path in auth.glob("*.spc"):
            shutil.copyfile(path, install / "config" / path.name)
    os.environ["STEAMPIPE_INSTALL_DIR"] = str(install)
    os.environ["STEAMPIPE_CONFIG_PATH"] = str(install / "config")
    os.environ["STEAMPIPE_UPDATE_CHECK"] = "false"
    os.environ["POWERPIPE_UPDATE_CHECK"] = "false"
    started = time.monotonic()
    try:
        steampipe = ["steampipe", "--install-dir", str(install)]
        plugins = subprocess.run([*steampipe, "plugin", "list", "--output", "json"], capture_output=True, text=True, timeout=30)
        (output / "plugins.log").write_text(plugins.stdout + plugins.stderr)
        if plugins.returncode or json.loads(plugins.stdout).get("failed"):
            raise RuntimeError("A selected Steampipe plugin is unavailable; the image and connection versions must match.")
        startup = subprocess.run([*steampipe, "service", "start", "--database-listen=local"], capture_output=True, text=True, timeout=120)
        (output / "startup.log").write_text(startup.stdout + startup.stderr)
        if startup.returncode:
            raise RuntimeError("Steampipe startup failed: " + startup.stderr[-3000:])
        # Wait for Steampipe to materialize connection schemas before Powerpipe
        # opens a direct database connection.
        initialized = subprocess.run([*steampipe, "query", "select schema_name from information_schema.schemata", "--output", "json"], capture_output=True, text=True, timeout=120)
        (output / "schemas.log").write_text(initialized.stdout + initialized.stderr)
        if initialized.returncode:
            raise RuntimeError("Steampipe connection initialization failed; provider coverage is unavailable.")
        if not args.self_test:
            schemas = {row.get("schema_name") for row in json.loads(initialized.stdout).get("rows", [])}
            if args.provider not in schemas:
                raise RuntimeError("Steampipe did not initialize the selected provider schema. Check plugin configuration and use a native CPU architecture; emulation can break plugin-manager detection.")
        if args.self_test:
            mod = runtime / "self-test"
            mod.mkdir()
            (mod / "mod.pp").write_text('''mod "smoke" {}
benchmark "all" {
  children = [control.fixture, control.failure]
}
control "fixture" {
  title = "Adapter fixture"
  sql = "select * from (values ('fixture:fail', 'alarm', 'Harden this resource'), ('fixture:pass', 'ok', 'Configured'), ('fixture:manual', 'info', 'Review manually'), ('fixture:skip', 'skip', 'Not applicable')) as t(resource, status, reason)"
}
control "failure" {
  title = "Coverage fixture"
  sql = "select * from deliberately_missing_table"
}
''')
            entries = [{"mod": "smoke", "version": "fixture", "benchmarks": ["all"], "directory": str(mod)}]
        else:
            entries = json.loads(pathlib.Path("/opt/bluepeass/catalog.json").read_text())[args.provider]
        for index, entry in enumerate(entries):
            if not args.self_test:
                # In particular, refresh the static GCP access token between
                # long suites without copying another account's default cache.
                for path in auth.glob("*.spc"):
                    destination = install / "config" / path.name
                    if path.read_bytes() != destination.read_bytes():
                        temporary = destination.with_suffix(".spc.tmp")
                        shutil.copyfile(path, temporary)
                        os.replace(temporary, destination)
                subprocess.run([*steampipe, "query", "select 1", "--output", "json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            directory = pathlib.Path(entry.get("directory", "/opt/bluepeass/mods/" + entry["mod"]))
            if not args.self_test:
                local_mod = runtime / entry["mod"]
                shutil.copytree(directory, local_mod)
                directory = local_mod
                result["query_context"].extend(prepare_query_context(directory, args.provider))
            # The RBAC scanner never reads Secret objects. Keep the same contract
            # for hardening; the omitted metadata check is reported explicitly.
            if args.provider == "kubernetes":
                version_path = auth / "kubernetes-version.json"
                version = json.loads(version_path.read_text()) if version_path.exists() else {}
                minor = re.sub(r"\D.*", "", str(version.get("minor", "")))
                removed_psp = str(version.get("major")) == "1" and bool(minor) and int(minor) >= 25
                for path in (directory / "all_controls").rglob("*.pp"):
                    text = path.read_text()
                    def exclude(match):
                        name = match.group(1)
                        if name == "secret_default_namespace_used":
                            reason = "Secret object reads are disabled."
                        elif removed_psp and (name.startswith("pod_security_policy_") or name.endswith("_container_argument_pod_security_policy_enabled") or name.endswith("_container_argument_security_context_deny_enabled")):
                            reason = "PodSecurityPolicy was removed in Kubernetes 1.25; this upstream check is not applicable."
                        elif str(version.get("major")) == "1" and bool(minor) and int(minor) >= 24 and name.endswith("_container_argument_insecure_port_0"):
                            reason = "The API server's insecure serving flags were removed in Kubernetes 1.24; absence of the removed flag is not insecure serving."
                        else:
                            return match.group(0)
                        result["excluded_controls"].append({"control_id": "kubernetes_compliance.control." + name, "reason": reason})
                        return ""
                    path.write_text(re.sub(r"^\s*control\.([\w]+),?\s*$", exclude, text, flags=re.MULTILINE))
            filename = output / f"benchmark-{index}.json"
            remaining = args.timeout - int(time.monotonic() - started)
            if remaining <= 0:
                result["errors"].append({"mod": entry["mod"], "error": "Hardening timeout reached before this suite."})
                continue
            command = ["powerpipe", "--install-dir", str(runtime / "powerpipe"), "benchmark", "run", *entry["benchmarks"], "--output", "none", "--export", str(filename),
                       "--input=false", "--progress=false", "--mod-install=false", "--max-parallel", "10", "--benchmark-timeout", str(remaining)]
            try:
                completed = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=remaining + 30)
                document = json.loads(filename.read_text()) if filename.exists() else None
                result["runs"].append({"mod": entry["mod"], "version": entry["version"], "exit_code": completed.returncode, "document": document})
                if document is None:
                    result["errors"].append({"mod": entry["mod"], "error": "Powerpipe produced no JSON export: " + completed.stderr[-3000:]})
            except subprocess.TimeoutExpired:
                result["errors"].append({"mod": entry["mod"], "error": "Powerpipe benchmark timed out."})
            (output / "result.json").write_text(json.dumps(result))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        result["errors"].append({"error": str(exc)})
    finally:
        (output / "result.json").write_text(json.dumps(result))
        try:
            subprocess.run(["steampipe", "--install-dir", str(install), "service", "stop", "--force"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            # The dedicated container's exit also terminates remaining workers.
            pass
        shutil.rmtree(runtime, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
