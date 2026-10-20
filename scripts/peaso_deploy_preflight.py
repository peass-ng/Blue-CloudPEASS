#!/usr/bin/env python3
"""Read only the dedicated hosted deployment and emit sanitized readiness facts."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from peaso import deployment
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from peaso_deploy import ACCOUNT, BUILD, ROOT, ZERO_IMAGE, verify_backend


def main():
    verify_backend()
    session = boto3.Session(region_name="us-east-1")
    identity = session.client("sts").get_caller_identity()
    if identity["Account"] != ACCOUNT:
        raise RuntimeError("Preflight requires the configured deployment account")
    facts = {"checked_at": datetime.now(timezone.utc).isoformat(), "account": ACCOUNT,
             "caller_role": identity["Arn"].split("/")[1],
             "backend": deployment.backend(),
             "errors": {}}

    def inspect(label, callback):
        try:
            facts[label] = callback()
        except ClientError as error:
            facts["errors"][label] = error.response.get("Error", {}).get("Code", "ClientError")

    def state():
        response = session.client("s3").get_object(Bucket=deployment.backend()["bucket"], Key=deployment.backend()["key"])
        with response["Body"] as body:
            value = json.loads(body.read())
        return {"serial": value.get("serial"), "managed_resources": [
            {"type": r["type"], "name": r["name"], "instances": len(r.get("instances", []))}
            for r in value.get("resources", []) if r.get("mode") == "managed"]}

    inspect("state", state)
    inspect("ecr", lambda: [{k: r.get(k) for k in ("repositoryArn", "repositoryUri", "imageTagMutability", "imageScanningConfiguration")}
                            for r in session.client("ecr").describe_repositories(repositoryNames=["hacktricks-cspm-worker"])["repositories"]])
    inspect("ecr_images", lambda: [{"digest": r["imageDigest"], "tags": r.get("imageTags", [])}
                                   for r in session.client("ecr").describe_images(repositoryName="hacktricks-cspm-worker")["imageDetails"]])
    inspect("cspm_lambda", lambda: {k: v for k, v in session.client("lambda").get_function_configuration(FunctionName="hacktricks-cspm-api").items()
                                   if k in ("FunctionName", "Runtime", "State", "LastUpdateStatus")})
    inspect("shared_client", lambda: {k: v for k, v in session.client("cognito-idp").describe_user_pool_client(
        UserPoolId=deployment.value("cognito_pool_id"), ClientId=deployment.value("cognito_client_id"))["UserPoolClient"].items()
        if k in ("UserPoolId", "ClientId", "ExplicitAuthFlows", "WriteAttributes", "ReadAttributes")})
    inspect("cloudfront", lambda: [{"id": r["Id"], "domain": r["DomainName"], "status": r["Status"], "aliases": r.get("Aliases", {}).get("Items", [])}
        for page in session.client("cloudfront").get_paginator("list_distributions").paginate()
        for r in page.get("DistributionList", {}).get("Items", [])
        if any(alias in {"cspm.hacktricks.wiki", "tools.hacktricks.wiki"} for alias in r.get("Aliases", {}).get("Items", []))])
    inspect("certificate", lambda: [{"arn": r["CertificateArn"], "domain": r["DomainName"], "status": r.get("Status")}
        for page in session.client("acm").get_paginator("list_certificates").paginate(CertificateStatuses=["ISSUED"])
        for r in page["CertificateSummaryList"] if r["DomainName"] in {"hacktricks.wiki", "*.hacktricks.wiki"}])
    variables_path = ROOT / "infra/aws/deployment.auto.tfvars.json"
    if variables_path.is_file():
        variables = json.loads(variables_path.read_text())
        facts["packaging"] = {"placeholder_image": variables.get("worker_image") == ZERO_IMAGE,
                              "api_zip_exists": Path(variables.get("api_zip", "/missing")).is_file()}
    if (BUILD / "release.json").is_file():
        release = json.loads((BUILD / "release.json").read_text())
        facts["historical_release"] = {"version": release["source_version"], "file_count": len(release["files"]),
                                       "includes_privesc": any(name.startswith("peaso/privesc/") for name in release["files"])}
    report = ROOT / ".cache/hosted-deploy/preflight.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(facts, indent=2) + "\n")
    report.chmod(0o600)
    print(json.dumps(facts, indent=2))


if __name__ == "__main__":
    main()
