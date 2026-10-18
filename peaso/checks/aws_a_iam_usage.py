"""Credential report observation windows use the captured UTC date, offline."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import register, result
from .facts import get, Unavailable
from .fixtures import CASES
from .aws_a_facts import captured_clock, csv_boolean

NATIVE_IDS = []


def report_date(item, field):
    value = get(item, field, str)
    if value in {"N/A", "no_information", "not_supported"}:
        return None
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise Unavailable("credential report date lacks timezone: " + field)
    return stamp


def usage_fixture(days):
    return {"user": "reviewer", "password_enabled": "true", "password_last_used": "N/A",
        "password_last_changed": "2026-10-09T00:00:00+00:00", "access_key_1_active": "false",
        "access_key_1_last_used_date": "N/A", "access_key_1_last_rotated": "N/A",
        "access_key_2_active": "false", "access_key_2_last_used_date": "N/A", "access_key_2_last_rotated": "N/A"}


for days in (45, 90):
    def install(days=days):
        cid = f"aws.a.iam.unused_credentials_{days}_days"
        @register(cid, "aws", "least_privilege", "iam_credential_report", f"Enabled IAM credentials avoid unobserved use beyond the captured {days}-day cutoff",
            "medium", "AC-6", "Review stale enabled credentials within AWS observation-window limits; prefer short-lived access.")
        def evaluate(item, index):
            user = get(item, "user", str)
            if user == "<root_account>":
                return "MANUAL", {"reason": "Pinned source treats root credentials as owner review", "user": user}
            clock = captured_clock(item, index).astimezone(timezone.utc)
            cutoff = clock.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days)
            stale = []
            for label, enabled_field, used_field, created_field in [
                ("password", "password_enabled", "password_last_used", "password_last_changed"),
                ("access_key_1", "access_key_1_active", "access_key_1_last_used_date", "access_key_1_last_rotated"),
                ("access_key_2", "access_key_2_active", "access_key_2_last_used_date", "access_key_2_last_rotated")]:
                enabled = csv_boolean(item, enabled_field)
                if not enabled:
                    continue
                used = report_date(item, used_field)
                created = report_date(item, created_field)
                if (used is not None and used < cutoff) or (used is None and created is not None and created < cutoff):
                    stale.append(label)
            return result(bool(stale), stale_enabled_credentials=stale, captured_cutoff=cutoff.isoformat(),
                semantics="Latest AWS-observed use; missing historical observation does not establish effective unused permissions")
        good = usage_fixture(days)
        bad = {**good, "password_last_changed": "2026-01-01T00:00:00+00:00"}
        CASES[cid] = {"pass": good, "fail": bad, "manual": {"user": "<root_account>"}, "missing": {}, "malformed": None,
            "index": {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}}
        NATIVE_IDS.append(cid)
    install()
