"""Main-only AWS explanation rows follow the exact active source contracts."""

import hashlib
import json
from pathlib import Path

import pytest

from peaso import privesc
from peaso.privesc.finding_explanation import evidence_summary
from tests.test_peaso_privesc_finding_explanations_review import projected

ROOT = Path(__file__).resolve().parents[1]
IDS = (
    'aws-apprunner-mutable-ecr-autodeploy',
    'aws-apprunner-updateservice',
    'aws-appstream-createappblockbuilderstreamingurl',
    'aws-appstream-createimagebuilderstreamingurl',
    'aws-appstream-createstreamingurl-existing-fleet',
    'aws-appsync-passrole-new-api-sigv4',
    'aws-athena-createpresignednotebookurl',
    'aws-athena-getsessionendpoint-spark-connect',
    'aws-athena-startcalculationexecution-existing-session',
    'aws-batch-submitjob-existing-definition',
    'aws-cognito-getopenidtokenfordeveloperidentity',
    'aws-cognito-getopenidtokenfordeveloperidentity-classic',
    'aws-cognito-setidentitypoolroles-developer-token',
    'aws-cognito-updateidentitypool-enable-classic-developer-token',
    'aws-cognito-updateidentitypool-enable-guest-classic-role',
    'aws-deadline-existing-queue-role-vend',
    'aws-deadline-existing-worker-role-vend',
    'aws-deadline-new-worker-existing-fleet-role-vend',
    'aws-dynamodb-putresourcepolicy-self-getitem',
    'aws-ecs-executecommand',
    'aws-emr-addjobflowsteps',
    'aws-emr-addjobflowsteps-runtime-role',
    'aws-flink-studio-presigned-url',
    'aws-gamelift-getcomputeaccess-shared-fleet-role',
    'aws-gameliftstreams-createstreamsessionadminshell',
    'aws-glue-overwrite-existing-job-script',
    'aws-iot-update-existing-alias-new-certificate',
    'aws-mwaa-s3-putobject-dag',
    'aws-quicksight-updateuser-admin',
    'aws-sagemaker-updatenotebookinstancelifecycleconfig',
    'aws-scheduler-passrole-updateschedule-self-grant',
    'aws-sns-settopicattributes-self-subscribe',
    'aws-sqs-setqueueattributes-self-receive',
    'aws-ssm-sendcommand-hybrid-role',
    'aws-ssm-startsession-hybrid-role',
 )
ENTRIES = {entry["id"]: entry for entry in privesc.catalog()["entries"]}
COPY = json.loads((ROOT / "peaso/privesc/finding_explanation.json").read_text())
LEDGER = json.loads((ROOT / "docs/evidence-reviews/privesc.json").read_text())["checks"]


@pytest.mark.parametrize("ident", IDS)
def test_new_aws_explanation_and_ledger_match_current_contract(ident):
    entry = ENTRIES[ident]
    row = LEDGER[ident]
    normalized = {key: value for key, value in entry.items() if not key.startswith("_")}
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    assert row["reviewed_contract_sha256"] == digest
    assert row["conditions_retained"] == [condition["id"] for condition in entry.get("conditions", [])]
    assert row["blockers_retained"] == entry.get("blockers", [])
    assert row["purpose"] == COPY[ident]["purpose"]
    for confidence in ("derived", "conditional", "unknown"):
        summary = evidence_summary(projected(entry, confidence))
        assert summary and row["purpose"] in summary and len(summary) <= 240
