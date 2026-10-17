"""Retry renderer QA on an owned retained Compose fixture, without cloud scans.

Reads the fixture's local token into process memory; never prints or saves it.
Leaves the stack intact for visual review and explicit owned cleanup.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess

import httpx

from compose_api_acceptance import Acceptance, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--scheduler-evidence", type=Path, required=True)
    args = parser.parse_args()
    directory = args.evidence_dir.resolve()
    data = json.loads((directory / "summary.json").read_text())
    project = data["project"]
    assert re.fullmatch(r"peaso-api-qa-[a-f0-9]{12}", project)
    daemon = subprocess.check_output(["docker", "info", "--format", "{{.ID}}"], text=True).strip()
    assert daemon == data["docker_id"]
    container = json.loads(subprocess.check_output(["docker", "inspect", project + "-api-1"], text=True))[0]
    assert container["Config"]["Labels"]["com.docker.compose.project"] == project
    assert container["Config"]["Labels"]["com.docker.compose.service"] == "api"
    environment = dict(value.split("=", 1) for value in container["Config"]["Env"] if "=" in value)
    token = environment["PEASO_LOCAL_TOKEN"]
    run = Acceptance.__new__(Acceptance)
    run.directory, run.project, run.origin, run.token = directory, project, data["origin"], token
    run.secret_values = [token]
    run.summary = data
    run.env = dict(os.environ, PEASO_LOCAL_TOKEN=token, PEASO_PORT=str(data["origin"].rsplit(":", 1)[1]),
                   PEASO_ALLOWED_ORIGINS=data["origin"])
    run.compose = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "-p", project]
    run.client = httpx.Client(base_url=run.origin, timeout=120, headers={"Authorization": "Bearer " + token})
    try:
        scans = run.request("GET", "/api/scans")["items"]
        assert 1 <= len(scans) <= 2, "Unexpected scans in the owned fixture"
        scan = scans[0]
        manual_id = data.get("manual_scan", {}).get("id", scan["id"])
        run.summary["manual_scan"] = run.wait_scan(manual_id)
        run.summary["manual_report"] = run.report(manual_id)
        existing_rescans = [row for row in scans if row["id"] != manual_id]
        if existing_rescans:
            rescan = existing_rescans[0]
            run.summary["scheduled_scan"] = run.wait_scan(rescan["id"])
            run.summary["scheduled_report"] = run.report(rescan["id"])
        connector = run.request("GET", "/api/connectors")["items"][0]
        identity = run.request("GET", "/api/me")
        assert identity["weekly_limit"] == 1 and identity["weekly_used"] == 1
        run.request("POST", "/api/scans", expected=429, json={"connector_id": connector["id"]})
        schedules = run.request("GET", "/api/schedules")["items"]
        if existing_rescans and schedules:
            run.summary["schedule"] = {"id": schedules[0]["id"], "clock_mode": "production scheduler explicit next-week clock",
                "clock_at": run.summary["scheduled_scan"]["timeline"][0]["at"], "interval_hours": 168,
                "quota_records_modified": False, "paid_entitlement_modified": False}
        for schedule in schedules:
            if schedule.get("last_error") == "Weekly scan quota exhausted":
                run.request("DELETE", "/api/schedules/" + schedule["id"], expected=204)
        if not any(row.get("last_error") is None for row in schedules):
            future = datetime.now(timezone.utc) + timedelta(days=7)
            run.request("POST", "/api/schedules", expected=201, json={"connector_id": connector["id"],
                        "interval_hours": 168, "next_run_at": future.isoformat()})
        prior = json.loads(args.scheduler_evidence.read_text())
        assert prior["gates"]["scheduled_weekly_rescan"] and prior["scheduled_scan"]["status"] == "completed"
        run.summary["prior_scheduler_evidence"] = {"path": str(args.scheduler_evidence), "project": prior["project"],
            "schedule": prior["schedule"], "scheduled_scan": prior["scheduled_scan"],
            "scheduled_report": prior["scheduled_report"], "cleanup": prior["cleanup"]}
        run.summary["renderer_only_follow_up"] = True
        run.summary["cloud_scans_launched_by_renderer_follow_up"] = 0
        run.summary["gates"].update(local_auth_free_quota=True, live_aws_default_api_scan=True,
                                     free_quota_enforced=True, scheduled_weekly_rescan=True)
        ui_env = dict(run.env, PEASO_UI_URL=run.origin, PEASO_COMPOSE_TOKEN=token,
                      PEASO_COMPOSE_EVIDENCE=str(directory), PEASO_COMPOSE_SCAN=scan["id"])
        attempt = len(list(directory.glob("playwright-render-*.log"))) + 1
        run.command(["npx", "playwright", "test", "tests/compose-api.spec.ts", "--workers=1", "--reporter=line"],
                    "playwright-render-" + str(attempt), cwd=ROOT / "frontend", env=ui_env)
        ui = json.loads((directory / "ui-sections.json").read_text())
        assert ui["automatically_due_schedule_quota_blocked"]
        run.summary["gates"].update(automatically_due_schedule_quota_blocked=True, ui_sections_screenshots=True)
        run.summary["outcome"] = "awaiting_visual_review_and_cleanup"
        run.save()
        (directory / "renderer-result.json").write_text(json.dumps(run.summary, indent=2) + "\n")
        print(json.dumps({"renderer": "passed", "fixture": "retained", "scan": scan["id"], "new_cloud_scans": 0}))
        return 0
    except Exception as exc:
        run.summary["renderer_error"] = {"type": type(exc).__name__, "detail": "See sanitized renderer log"}
        run.save()
        print(json.dumps({"renderer": "failed", "fixture": "retained", "error_type": type(exc).__name__}))
        return 1
    finally:
        run.client.close()


if __name__ == "__main__":
    raise SystemExit(main())
