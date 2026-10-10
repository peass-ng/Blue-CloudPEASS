"""Keep customer permissions aligned with declared, configuration-only AWS reads."""
import json
from pathlib import Path


def refresh(root: Path):
    import sys
    sys.path.insert(0, str(root))
    import botocore.session
    from botocore import xform_name
    from peaso.collectors.aws import READ_ACTIONS
    session = botocore.session.get_session()
    prefixes = {"elbv2": "elasticloadbalancing", "elb": "elasticloadbalancing",
                "docdb": "rds", "neptune": "rds", "opensearch": "es",
                "s3control": "s3", "apigatewayv2": "apigateway"}
    special = {("s3", "list_buckets"): "s3:ListAllMyBuckets",
               ("s3", "get_public_access_block"): "s3:GetBucketPublicAccessBlock",
               ("s3", "get_bucket_encryption"): "s3:GetEncryptionConfiguration",
               ("s3control", "get_public_access_block"): "s3:GetAccountPublicAccessBlock"}
    forbidden = {"get_secret_value", "get_parameter", "get_parameters", "get_parameters_by_path",
                 "get_password_data", "get_object", "get_log_events", "filter_log_events",
                 "get_function", "get_api_key", "get_api_keys", "list_api_keys"}
    actions = set()
    gateway = False
    for service, operation in sorted(READ_ACTIONS):
        if service == "sts":
            continue  # GetCallerIdentity is intrinsic; no customer role-chain grant.
        if (service, operation) == ("iam", "generate_credential_report"):
            continue  # User-authorized evidence operation stays a separate statement.
        if operation in forbidden or not operation.startswith(("list_", "get_", "describe_", "batch_get_")):
            raise ValueError(f"Operation outside customer configuration-only policy: {service}/{operation}")
        if service in {"apigateway", "apigatewayv2"}:
            gateway = True
            continue
        model = session.get_service_model(service)
        names = {xform_name(name): name for name in model.operation_names}
        actions.add(special.get((service, operation), prefixes.get(service, service) + ":" + names[operation]))
    statements = [{"Sid": "ConfigurationAndInventoryRead", "Effect": "Allow",
                   "Action": sorted(actions), "Resource": "*"},
                  {"Sid": "CredentialReportEvidenceGeneration", "Effect": "Allow",
                   "Action": "iam:GenerateCredentialReport", "Resource": "*"}]
    if gateway:
        statements.append({"Sid": "ApiGatewayConfigurationRead", "Effect": "Allow", "Action": "apigateway:GET",
                           "Resource": ["arn:aws:apigateway:*::/restapis", "arn:aws:apigateway:*::/restapis/*",
                                        "arn:aws:apigateway:*::/apis", "arn:aws:apigateway:*::/apis/*"]})
    policy = {"Version": "2012-10-17", "Statement": statements}
    if len(json.dumps(policy, separators=(",", ":"))) >= 10000:
        raise ValueError("Customer inline role policy exceeds IAM's aggregate size limit")
    path = root / "infra/aws/customer-role.json"
    template = json.loads(path.read_text())
    template["Resources"]["AuditRole"]["Properties"]["Policies"][0]["PolicyDocument"] = policy
    path.write_text(json.dumps(template, indent=2) + "\n")
    print(f"Customer policy: {len(actions)} exact metadata actions, scoped API Gateway GET, and authorized credential-report generation")


if __name__ == "__main__":
    refresh(Path(__file__).resolve().parents[1])
