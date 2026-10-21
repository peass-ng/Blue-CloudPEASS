"""Public workload and runtime privilege must both be recorded for a finding."""

import json
from pathlib import Path

from peaso.snapshot import make_snapshot, resources
from peaso.principal_exposure import exposed_privileged_findings
from peaso.analysis.exposure_dedup import deduplicate_principal_exposure
from peaso.analysis import analyze_findings
from peaso.analysis import REQUIRED_TYPES as ANALYSIS_REQUIRED_TYPES
from peaso.analysis.internet_exposure import assess
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_facts_compute_edge import _api_domain_mappings, _http_api_domain_mappings, _http_integration, _rest_api_method


def snapshot(provider, items, scope):
    return make_snapshot(provider, [scope], [{"type": kind, "scope": scope, "service": kind,
        "status": "collected" if rows else "empty", "items": rows} for kind, rows in items.items()])


def findings(snap):
    return exposed_privileged_findings(snap, resources(snap))


def assert_exposure_in_report(snap, monkeypatch):
    import peaso.remediation as remediation
    from peaso.engine import evaluate_snapshot
    monkeypatch.setattr(remediation, "report_templates", lambda check_ids, provider=None: {})
    report = evaluate_snapshot(snap, categories=["exposure"], checks=["analysis.exposed_privileged_workload"])
    assert report["stats"]["categories"] == ["exposure"]
    assert any(row["check_id"] == "analysis.exposed_privileged_workload" and row["status"] == "FAIL"
        for row in report["findings"])


def test_aws_public_lambda_uses_administrator_role(monkeypatch):
    arn = "arn:aws:iam::111111111111:role/app"
    snap = snapshot("aws", {
        "iam_role": [{"Arn": arn, "RoleName": "app", "RolePolicyList": [{"PolicyName": "admin",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}],
        "lambda_function": [{"FunctionName": "web", "Role": arn,
            "FunctionUrl": {"FunctionUrl": "https://web.lambda-url.us-east-1.on.aws/", "AuthType": "NONE"},
            "Policy": {"Policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                "Action": "lambda:InvokeFunctionUrl", "Resource": "*"}]}}}],
    }, "111111111111/us-east-1")
    result = findings(snap)
    assert len(result) == 1 and result[0]["status"] == "FAIL"
    assert result[0]["evidence"]["principal"] == arn
    assert "Action" in str(result[0]["evidence"]["grant_sources"])
    assert len(result[0]["evidence_summary"].splitlines()) == 4
    assert any(row["check_id"] == "analysis.exposed_privileged_workload" and row["status"] == "FAIL"
        for row in analyze_findings(snap))
    # The finding must also survive category/check selection in the full report.
    # Remediation templates are unrelated to this derived exposure path.
    import peaso.remediation as remediation
    from peaso.engine import evaluate_snapshot
    monkeypatch.setattr(remediation, "report_templates", lambda check_ids, provider=None: {})
    report = evaluate_snapshot(snap, categories=["exposure"], checks=["analysis.exposed_privileged_workload"])
    assert [row["status"] for row in report["findings"] if row["check_id"] == "analysis.exposed_privileged_workload"] == ["FAIL"]


def test_public_workloads_use_the_least_privilege_risk_catalog_for_specific_actions():
    role = "arn:aws:iam::111111111111:role/web"
    aws = snapshot("aws", {
        "iam_role": [{"Arn": role, "RolePolicyList": [{"PolicyName": "pass-role",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::111111111111:role/deployer"}]}}]}],
        "lambda_function": [{"FunctionName": "web", "Role": role,
            "FunctionUrl": {"FunctionUrl": "https://web.lambda-url.us-east-1.on.aws/", "AuthType": "NONE"},
            "Policy": {"Policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                "Action": "lambda:InvokeFunctionUrl", "Resource": "*"}]}}}],
    }, "111111111111/us-east-1")
    aws_result = findings(aws)
    assert len(aws_result) == 1
    assert "iam:PassRole" in aws_result[0]["evidence_summary"]
    assert aws_result[0]["evidence"]["grant_sources"][0]["grants"][0]["severity"] == "critical"

    definition = "/subscriptions/home/providers/Microsoft.Authorization/roleDefinitions/assigner"
    azure = snapshot("azure", {
        "role_definition": [{"name": "assigner", "properties": {"permissions": [
            {"actions": ["Microsoft.Authorization/roleAssignments/write"], "dataActions": []}]}}],
        "role_assignment": [{"properties": {"principalId": "mi", "roleDefinitionId": definition,
            "scope": "/subscriptions/home"}}],
        "container_group": [{"id": "container", "identity": {"principalId": "mi"}, "properties": {
            "provisioningState": "Succeeded", "ipAddress": {"type": "Public", "ip": "8.8.8.8",
                "ports": [{"port": 8080}]}}}],
    }, "/subscriptions/home")
    azure_result = findings(azure)
    assert len(azure_result) == 1
    assert "Microsoft.Authorization/roleAssignments/write" in azure_result[0]["evidence_summary"]
    assert azure_result[0]["evidence"]["grant_sources"][0]["grants"][0]["severity"] == "critical"


def test_grouped_view_keeps_each_public_workload_and_explains_the_shared_risk():
    from peaso.finding_groups import group_findings

    role = "arn:aws:iam::111111111111:role/web"
    snap = snapshot("aws", {
        "iam_role": [{"Arn": role, "RolePolicyList": [{"PolicyName": "admin",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}],
        "lambda_function": [{"FunctionName": name, "Role": role,
            "FunctionUrl": {"FunctionUrl": f"https://{name}.lambda-url.us-east-1.on.aws/", "AuthType": "NONE"},
            "Policy": {"Policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                "Action": "lambda:InvokeFunctionUrl", "Resource": "*"}]}}} for name in ("web-one", "web-two")],
    }, "111111111111/us-east-1")
    individual = findings(snap)
    grouped = group_findings(individual, observations=True)
    assert len(individual) == 2 and len(grouped) == 1
    assert grouped[0]["affected_asset_count"] == 2
    assert len(grouped[0]["evidence_summary"].splitlines()) == 3
    assert "2 workloads are linked to configured public entry points" in grouped[0]["evidence_summary"]
    assert {row["resource_id"] for row in grouped[0]["observations"]} == {
        row["resource_id"] for row in individual}


def test_aws_exposure_collects_attached_policy_and_reports_its_privilege(monkeypatch):
    from peaso.engine import plan_collection
    role = "arn:aws:iam::111111111111:role/web"
    policy = "arn:aws:iam::111111111111:policy/web-broad"
    assert "iam_policy" in ANALYSIS_REQUIRED_TYPES["aws"]["exposure"]
    assert "iam_policy" in plan_collection({"connector": {"provider": "aws", "scopes": ["111111111111/us-east-1"]},
        "checks": ["analysis.exposed_privileged_workload"]})
    assert "iam_policy" in plan_collection({"connector": {"provider": "aws", "scopes": ["111111111111/us-east-1"]},
        "categories": ["exposure"]})
    snap = snapshot("aws", {
        "iam_role": [{"Arn": role, "RoleName": "web", "AttachedManagedPolicies": [{"PolicyArn": policy}]}],
        "iam_policy": [{"Arn": policy, "PolicyVersionList": [{"IsDefaultVersion": True,
            "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}]}],
        "lambda_function": [{"FunctionName": "web", "Role": role,
            "FunctionUrl": {"FunctionUrl": "https://web.lambda-url.us-east-1.on.aws/", "AuthType": "NONE"},
            "Policy": {"Policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                "Action": "lambda:InvokeFunctionUrl", "Resource": "*"}]}}}],
    }, "111111111111/us-east-1")
    result = findings(snap)
    assert len(result) == 1 and result[0]["status"] == "FAIL"
    assert any(source["grant_source_id"] != source["resource_id"] for source in result[0]["evidence"]["grant_sources"])
    assert_exposure_in_report(snap, monkeypatch)


def test_aws_custom_domain_maps_public_api_to_privileged_lambda():
    arn = "arn:aws:lambda:us-east-2:111111111111:function:api"
    role = "arn:aws:iam::111111111111:role/api"
    snap = snapshot("aws", {
        "iam_role": [{"Arn": role, "RoleName": "api", "RolePolicyList": [{"PolicyName": "admin",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}],
        "lambda_function": [{"FunctionArn": arn, "FunctionName": "api", "Role": role}],
        "rest_api": [{"id": "abc123", "disableExecuteApiEndpoint": True,
            "endpointConfiguration": {"types": ["REGIONAL"]},
            "Methods": [{"path": "/", "httpMethod": "GET", "authorizationType": "NONE",
                "integrationLambdaArn": arn + ":live"}]}],
        "rest_api_method": [{"id": "deployed-get", "restApiId": "abc123", "resourcePath": "/",
            "httpMethod": "GET", "stageArn": "arn:aws:apigateway:us-east-2::/restapis/abc123/stages/live"}],
        "apigateway_domain_name": [{"domainName": "api.example.com", "endpointConfiguration": {"types": ["REGIONAL"]}, "BasePathMappings": {
            "collection_status": "collected", "items": [{"restApiId": "abc123", "stage": "live"}]}}],
    }, "111111111111/us-east-2")
    result = findings(snap)
    assert len(result) == 1
    assert "https://api.example.com" in result[0]["evidence_summary"]
    assert result[0]["evidence"]["principal"] == role
    assert "execute-api" not in result[0]["evidence_summary"]
    domain = next(c for c in snap["collections"] if c["type"] == "apigateway_domain_name")
    domain["items"][0]["endpointConfiguration"] = {"types": ["PRIVATE"]}
    assert findings(snap) == []
    domain["items"][0]["endpointConfiguration"] = {"types": ["REGIONAL"]}
    domain["items"][0]["BasePathMappings"]["items"][0]["restApiId"] = "another-api"
    assert findings(snap) == []
    state = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "rest_api")
    assert state.verdict() == "PASS"
    domain["status"] = "partial"
    state = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "rest_api")
    assert state.verdict() == "UNKNOWN"
    domain["status"] = "collected"
    domain["items"][0]["routingMode"] = "ROUTING_RULE_ONLY"
    state = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "rest_api")
    assert state.verdict() == "UNKNOWN"


def test_undeployed_api_method_does_not_link_to_lambda_role():
    arn = "arn:aws:lambda:us-east-2:111111111111:function:api"
    role = "arn:aws:iam::111111111111:role/api"
    snap = snapshot("aws", {
        "iam_role": [{"Arn": role, "RolePolicyList": [{"PolicyName": "admin",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}],
        "lambda_function": [{"FunctionArn": arn, "Role": role}],
        "rest_api": [{"id": "abc123", "disableExecuteApiEndpoint": False,
            "endpointConfiguration": {"types": ["REGIONAL"]},
            "Methods": [{"path": "/new", "httpMethod": "GET", "integrationLambdaArn": arn}]}],
        "rest_api_method": [{"id": "deployed-get", "restApiId": "abc123", "resourcePath": "/old",
            "httpMethod": "GET", "stageArn": "arn:aws:apigateway:us-east-2::/restapis/abc123/stages/live"}],
    }, "111111111111/us-east-2")
    assert findings(snap) == []


def test_aws_http_api_custom_domain_maps_to_autodeployed_privileged_lambda():
    arn = "arn:aws:lambda:us-east-2:111111111111:function:http-api"
    role = "arn:aws:iam::111111111111:role/http-api"
    snap = snapshot("aws", {
        "iam_role": [{"Arn": role, "RolePolicyList": [{"PolicyName": "admin",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}],
        "lambda_function": [{"FunctionArn": arn, "Role": role}],
        "http_api": [{"ApiId": "http123", "ProtocolType": "HTTP", "DisableExecuteApiEndpoint": True,
            "Routes": {"collection_status": "collected", "items": [{"RouteKey": "GET /",
                "AuthorizationType": "NONE", "Target": "integrations/int1"}]},
            "Integrations": {"collection_status": "collected", "items": [{"IntegrationId": "int1",
                "integrationLambdaArn": arn}]}}],
        "http_api_stage": [{"id": "stage", "ParentApiId": "http123", "StageName": "$default",
            "AutoDeploy": True}],
        "apigatewayv2_domain_name": [{"DomainName": "api.example.com", "DomainNameConfigurations": [
            {"EndpointType": "REGIONAL"}], "ApiMappings": {"collection_status": "collected",
            "items": [{"ApiId": "http123", "Stage": "$default"}]}}],
    }, "111111111111/us-east-2")
    result = findings(snap)
    assert len(result) == 1
    assert "https://api.example.com" in result[0]["evidence_summary"]
    domain = next(c for c in snap["collections"] if c["type"] == "apigatewayv2_domain_name")
    unnamed = dict(domain["items"][0])
    unnamed.pop("DomainName")
    domain["items"].append(unnamed)
    assert len(findings(snap)) == 1
    domain["items"].pop()
    stages = next(c for c in snap["collections"] if c["type"] == "http_api_stage")
    stages["items"][0]["AutoDeploy"] = False
    assert findings(snap) == []
    stages["items"][0]["AutoDeploy"] = True
    api = next(c for c in snap["collections"] if c["type"] == "http_api")
    api["items"][0]["Routes"]["items"][0]["AuthorizationType"] = "JWT"
    assert len(findings(snap)) == 1
    state = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "http_api")
    assert state.authenticated and state.verdict() == "PASS"
    api["items"][0]["Routes"]["items"][0]["AuthorizationType"] = "NONE"
    domain["items"][0]["ApiMappings"]["items"] = []
    domain["status"] = "partial"
    assert findings(snap) == []
    state = next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "http_api")
    assert state.verdict() == "UNKNOWN"


def test_healthy_public_alb_target_links_only_its_ecs_task_role():
    role = "arn:aws:iam::111111111111:role/web"
    lb = "arn:aws:elasticloadbalancing:us-east-2:111111111111:loadbalancer/app/web/1"
    tg = "arn:aws:elasticloadbalancing:us-east-2:111111111111:targetgroup/web/1"
    task_definition = "arn:aws:ecs:us-east-2:111111111111:task-definition/web:1"
    snap = snapshot("aws", {
        "iam_role": [{"Arn": role, "RolePolicyList": [{"PolicyName": "admin",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}],
        "vpc": [{"VpcId": "vpc-1"}],
        "subnet": [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
        "security_group": [{"GroupId": "sg-lb", "VpcId": "vpc-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
        "network_acl": [{"NetworkAclId": "acl-1", "VpcId": "vpc-1",
            "Associations": [{"SubnetId": "subnet-1"}], "Entries": [
                {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"},
                {"RuleNumber": 100, "Egress": True, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"}]}],
        "load_balancer": [{"LoadBalancerArn": lb, "Type": "application", "Scheme": "internet-facing",
            "DNSName": "web.example.elb.amazonaws.com", "VpcId": "vpc-1", "SecurityGroups": ["sg-lb"],
            "AvailabilityZones": [{"SubnetId": "subnet-1"}], "Listeners": {"collection_status": "collected",
                "items": [{"Port": 443, "Protocol": "HTTPS", "DefaultActions": [
                    {"Type": "forward", "TargetGroupArn": tg}]}]}}],
        "target_group": [{"TargetGroupArn": tg, "LoadBalancerArns": [lb], "TargetType": "ip",
            "TargetHealth": {"collection_status": "collected", "TargetHealthDescriptions": [
                {"Target": {"Id": "10.0.1.5", "Port": 8080}, "TargetHealth": {"State": "healthy"}}]}}],
        "ecs_service": [{"serviceName": "web", "taskDefinition": task_definition,
            "loadBalancers": [{"targetGroupArn": tg, "containerPort": 8080}]}],
        "ecs_task_definition": [{"taskDefinitionArn": task_definition, "taskRoleArn": role}],
        "ecs_task": [{"taskArn": "task-web", "group": "service:web", "lastStatus": "RUNNING",
            "taskDefinitionArn": task_definition, "attachments": [{"details": [
                {"name": "networkInterfaceId", "value": "eni-web"}]}]}],
        "network_interface": [{"NetworkInterfaceId": "eni-web", "PrivateIpAddress": "10.0.1.5"}],
    }, "111111111111/us-east-2")
    result = findings(snap)
    assert len(result) == 1 and result[0]["evidence"]["principal"] == role
    assert result[0]["evidence_summary"].startswith("task-web is linked to a public endpoint")
    listener = next(c for c in snap["collections"] if c["type"] == "load_balancer")["items"][0]["Listeners"]["items"][0]
    listener["DefaultActions"] = [{"Type": "fixed-response"}]
    listener["Rules"] = {"collection_status": "collected", "items": [{"Priority": "1", "Conditions": [], "Actions": [
        {"Type": "forward", "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": tg, "Weight": 1}]}}]}]}
    routed = findings(snap)
    assert len(routed) == 1
    assert routed[0]["evidence"]["endpoints"][0]["backend_evidence"]["target_group"] == tg
    assert routed[0]["evidence"]["endpoints"][0]["backend_evidence"]["healthy_target"] == {
        "ip": "10.0.1.5", "port": 8080}
    listener["Rules"]["items"][0]["Actions"][0]["TargetGroupArn"] = tg
    listener["Rules"]["items"][0]["Actions"][0]["ForwardConfig"]["TargetGroups"][0]["Weight"] = 0
    assert findings(snap) == []
    listener["Rules"]["items"][0]["Actions"][0]["ForwardConfig"]["TargetGroups"][0]["Weight"] = 1
    listener["Rules"]["items"][0]["Conditions"] = [{"Field": "source-ip", "Values": ["10.0.0.0/8"]}]
    assert findings(snap) == []
    listener["Rules"]["items"][0]["Conditions"][0]["Values"] = ["0.0.0.0/0"]
    assert len(findings(snap)) == 1
    tg_collection = next(c for c in snap["collections"] if c["type"] == "target_group")
    tg_collection["items"][0]["TargetHealth"]["TargetHealthDescriptions"][0]["TargetHealth"]["State"] = "unhealthy"
    assert findings(snap) == []


def test_api_collector_keeps_only_backend_identity_and_mapping_metadata():
    class Requests:
        def pages(self, session, service, region, operation, expression, **kwargs):
            assert (service, region, operation, expression, kwargs) == (
                "apigateway", "us-east-2", "get_base_path_mappings", "items",
                {"domainName": "api.example.com"})
            return ReadResult([{"basePath": "v1", "restApiId": "abc123", "stage": "live",
                "extra": "unneeded"}])

    domains = _api_domain_mappings(Requests(), None, "us-east-2", [{"domainName": "api.example.com"}])
    assert domains[0]["BasePathMappings"] == {"collection_status": "collected", "items": [
        {"basePath": "v1", "restApiId": "abc123", "stage": "live"}]}
    method = _rest_api_method({"id": "resource", "resourceMethods": {"GET": {
        "authorizationType": "NONE", "methodIntegration": {"uri":
            "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/"
            "arn:aws:lambda:us-east-2:111111111111:function:api:live/invocations"}}}})
    assert method["resourceMethods"]["GET"]["integrationLambdaArn"] == (
        "arn:aws:lambda:us-east-2:111111111111:function:api:live")
    integration = _http_integration({"IntegrationId": "int1", "IntegrationUri":
        "arn:aws:lambda:us-east-2:111111111111:function:http-api:live", "CredentialsArn": "private"})
    assert integration == {"IntegrationId": "int1", "integrationLambdaArn":
        "arn:aws:lambda:us-east-2:111111111111:function:http-api:live"}

    class V2Requests:
        def pages(self, session, service, region, operation, expression, **kwargs):
            assert (service, region, operation, expression, kwargs) == (
                "apigatewayv2", "us-east-2", "get_api_mappings", "Items", {"DomainName": "api.example.com"})
            return ReadResult([{"ApiId": "http123", "Stage": "$default", "ApiMappingKey": "v1"}])

    v2 = _http_api_domain_mappings(V2Requests(), None, "us-east-2", [{"DomainName": "api.example.com"}])
    assert v2[0]["ApiMappings"]["items"] == [{"ApiId": "http123", "Stage": "$default", "ApiMappingKey": "v1"}]


def test_customer_role_can_read_api_custom_domain_mappings():
    root = Path(__file__).resolve().parents[1]
    for filename in ("customer-role.json", "customer-policy-allocation.json"):
        role = json.loads((root / "infra/aws" / filename).read_text())
        statements = [statement for resource in role["Resources"].values()
            for statement in resource.get("Properties", {}).get("PolicyDocument", {}).get("Statement", [])]
        api_read = next(statement for statement in statements if statement.get("Sid") == "ApiGatewayConfigurationRead")
        assert api_read["Action"] == "apigateway:GET"
        for suffix in ("/domainnames/*/basepathmappings", "/domainnames/*/apimappings", "/apis/*/integrations"):
            assert {"Fn::Sub": "arn:${AWS::Partition}:apigateway:*::" + suffix} in api_read["Resource"]


def test_gcp_public_cloud_run_uses_owner_service_account(monkeypatch):
    email = "app@home.iam.gserviceaccount.com"
    snap = snapshot("gcp", {
        "iam_policy": [{"bindings": [{"role": "roles/owner", "members": ["serviceAccount:" + email]}]}],
        "service_account": [{"email": email}],
        "cloudrun_service": [{"name": "projects/home/locations/us/services/web",
            "uri": "https://web.run.app", "ingress": "INGRESS_TRAFFIC_ALL",
            "invokerIamDisabled": True, "template": {"serviceAccount": email}}],
    }, "projects/home")
    result = findings(snap)
    assert len(result) == 1 and result[0]["evidence"]["principal"] == email
    assert "roles/owner" in result[0]["evidence_summary"]
    assert_exposure_in_report(snap, monkeypatch)


def test_gcp_public_load_balancer_links_only_healthy_backend_vm():
    base = "https://www.googleapis.com/compute/v1/projects/home"
    service = base + "/global/backendServices/web"
    vm = base + "/zones/us-central1-a/instances/web"
    email = "web@home.iam.gserviceaccount.com"
    snap = snapshot("gcp", {
        "iam_policy": [{"bindings": [{"role": "roles/owner", "members": ["serviceAccount:" + email]}]}],
        "service_account": [{"email": email}],
        "instance": [{"name": "web", "selfLink": vm, "status": "RUNNING",
            "serviceAccounts": [{"email": email}]}],
        "forwarding_rule": [{"name": "front", "IPAddress": "203.0.113.10",
            "loadBalancingScheme": "EXTERNAL_MANAGED", "IPProtocol": "TCP", "portRange": "443",
            "target": base + "/global/targetHttpsProxies/web"}],
        "target_proxy": [{"name": "web", "selfLink": base + "/global/targetHttpsProxies/web",
            "service": service}],
        "backend_service": [{"name": "web", "selfLink": service,
            "BackendHealth": {"collection_status": "collected", "groups": [{"collection_status": "collected",
                "group": base + "/zones/us-central1-a/instanceGroups/web",
                "healthStatus": [{"instance": vm, "healthState": "HEALTHY"}]}]}}],
    }, "projects/home")
    result = findings(snap)
    assert len(result) == 1 and result[0]["evidence"]["principal"] == email
    assert result[0]["evidence"]["endpoints"][0]["backend_evidence"]["health_state"] == "HEALTHY"
    health = next(c for c in snap["collections"] if c["type"] == "backend_service")["items"][0]["BackendHealth"]
    health["groups"][0]["healthStatus"][0]["healthState"] = "UNHEALTHY"
    assert findings(snap) == []
    health["groups"][0]["healthStatus"][0]["healthState"] = "HEALTHY"
    health["groups"][0]["collection_status"] = "denied"
    assert findings(snap) == []
    health["groups"][0]["collection_status"] = "collected"
    instance = next(c for c in snap["collections"] if c["type"] == "instance")["items"][0]
    instance["status"] = "TERMINATED"
    assert findings(snap) == []
    instance["status"] = "RUNNING"
    protected = next(c for c in snap["collections"] if c["type"] == "backend_service")["items"][0]
    protected["securityPolicy"] = base + "/global/securityPolicies/protected"
    open_service = base + "/global/backendServices/other"
    next(c for c in snap["collections"] if c["type"] == "backend_service")["items"].append({
        "name": "other", "selfLink": open_service,
        "BackendHealth": {"collection_status": "collected", "groups": []}})
    proxy = next(c for c in snap["collections"] if c["type"] == "target_proxy")["items"][0]
    proxy.pop("service")
    proxy["urlMap"] = base + "/global/urlMaps/web"
    snap["collections"].append({"type": "url_map", "scope": "projects/home", "service": "url_map",
        "status": "collected", "items": [{"name": "web", "selfLink": proxy["urlMap"],
            "defaultService": service, "pathMatchers": [{"defaultService": open_service}]}]})
    assert findings(snap) == []


def test_gcp_public_cloud_run_uses_high_impact_custom_role_permission():
    email = "app@home.iam.gserviceaccount.com"
    role = "projects/home/roles/tokenMinter"
    snap = snapshot("gcp", {
        "iam_policy": [{"bindings": [{"role": role, "members": ["serviceAccount:" + email]}]}],
        "iam_role": [{"name": role, "includedPermissions": ["iam.serviceAccounts.getAccessToken"]}],
        "service_account": [{"email": email}],
        "cloudrun_service": [{"name": "projects/home/locations/us/services/web",
            "uri": "https://web.run.app", "ingress": "INGRESS_TRAFFIC_ALL",
            "invokerIamDisabled": True, "template": {"serviceAccount": email}}],
    }, "projects/home")
    result = findings(snap)
    assert len(result) == 1
    assert "iam.serviceAccounts.getAccessToken" in result[0]["evidence_summary"]


def test_azure_public_container_uses_owner_identity(monkeypatch):
    definition = "/subscriptions/home/providers/Microsoft.Authorization/roleDefinitions/owner"
    snap = snapshot("azure", {
        "role_definition": [{"name": "owner", "properties": {"roleName": "Owner",
            "permissions": [{"actions": ["*"], "dataActions": []}]}}],
        "role_assignment": [{"properties": {"principalId": "mi", "roleDefinitionId": definition,
            "scope": "/subscriptions/home"}}],
        "container_group": [{"id": "container", "identity": {"principalId": "mi"}, "properties": {
            "provisioningState": "Succeeded", "ipAddress": {"type": "Public", "ip": "8.8.8.8",
                "ports": [{"port": 8080}]}}}],
    }, "/subscriptions/home")
    result = findings(snap)
    assert len(result) == 1 and result[0]["evidence"]["principal"] == "mi"
    assert result[0]["evidence"]["grant_sources"][0]["grant_source_id"]
    assert_exposure_in_report(snap, monkeypatch)


def test_azure_public_load_balancer_links_allowed_backend_vm_identity():
    base = "/subscriptions/home/resourceGroups/rg/providers/Microsoft.Network/"
    lb, nic, vm = base + "loadBalancers/web", base + "networkInterfaces/web", base + "virtualMachines/web"
    front, pool = lb + "/frontendIPConfigurations/public", lb + "/backendAddressPools/web"
    subnet, public_ip = base + "virtualNetworks/app/subnets/web", base + "publicIPAddresses/web"
    snap = snapshot("azure", {
        "role_definition": [{"name": "owner", "properties": {"roleName": "Owner",
            "permissions": [{"actions": ["*"], "dataActions": []}]}}],
        "role_assignment": [{"properties": {"principalId": "mi", "roleDefinitionId":
            "/subscriptions/home/providers/Microsoft.Authorization/roleDefinitions/owner",
            "scope": "/subscriptions/home"}}],
        "vm": [{"id": vm, "identity": {"principalId": "mi"}}],
        "subnet": [{"id": subnet, "properties": {}}],
        "nic": [{"id": nic, "properties": {"virtualMachine": {"id": vm},
            "ipConfigurations": [{"id": nic + "/ipConfigurations/primary", "properties": {
                "subnet": {"id": subnet}, "privateIPAddress": "10.0.1.5",
                "loadBalancerBackendAddressPools": [{"id": pool}]}}]}}],
        "public_ip": [{"id": public_ip, "properties": {"ipAddress": "8.8.8.8"}},
            {"id": public_ip + "-unused", "properties": {"ipAddress": "9.9.9.9"}}],
        "load_balancer": [{"id": lb, "sku": {"name": "Basic"}, "properties": {
            "frontendIPConfigurations": [{"id": front, "properties": {"publicIPAddress": {"id": public_ip}}},
                {"id": front + "-unused", "properties": {"publicIPAddress": {"id": public_ip + "-unused"}}}],
            "loadBalancingRules": [{"name": "web", "properties": {"frontendIPConfiguration": {"id": front},
                "backendAddressPool": {"id": pool}, "protocol": "Tcp", "frontendPort": 443,
                "backendPort": 443}}]}}],
    }, "/subscriptions/home")
    result = findings(snap)
    assert len(result) == 1 and result[0]["evidence"]["principal"] == "mi"
    assert "8.8.8.8" in result[0]["evidence_summary"]
    assert "9.9.9.9" not in result[0]["evidence_summary"]
    assert result[0]["evidence"]["endpoints"][0]["backend_evidence"][0]["public_ip"] == "8.8.8.8"
    other_nic, other_vm, other_pool = nic + "-other", vm + "-other", pool + "-other"
    next(c for c in snap["collections"] if c["type"] == "vm")["items"].append({
        "id": other_vm, "identity": {"principalId": "other-mi"}})
    next(c for c in snap["collections"] if c["type"] == "nic")["items"].append({
        "id": other_nic, "properties": {"virtualMachine": {"id": other_vm}, "ipConfigurations": [{
            "id": other_nic + "/ipConfigurations/primary", "properties": {"subnet": {"id": subnet},
                "privateIPAddress": "10.0.1.6", "loadBalancerBackendAddressPools": [{"id": other_pool}]}}]}})
    lb_props = next(c for c in snap["collections"] if c["type"] == "load_balancer")["items"][0]["properties"]
    lb_props["loadBalancingRules"].append({"name": "other", "properties": {
        "frontendIPConfiguration": {"id": front + "-unused"}, "backendAddressPool": {"id": other_pool},
        "protocol": "Tcp", "frontendPort": 8443, "backendPort": 8443}})
    result = findings(snap)
    assert len(result) == 1 and "9.9.9.9" not in result[0]["evidence_summary"]
    assert result[0]["evidence"]["endpoints"][0]["ports"] == ["tcp/443"]
    nic_collection = next(c for c in snap["collections"] if c["type"] == "nic")
    nic_collection["items"][0]["properties"]["ipConfigurations"][0]["properties"]["loadBalancerBackendAddressPools"] = []
    assert findings(snap) == []


def test_kubernetes_public_service_uses_cluster_admin_service_account(monkeypatch):
    snap = snapshot("k8s", {
        "networkpolicy": [],
        "service": [{"metadata": {"name": "web", "namespace": "app"}, "spec": {"type": "LoadBalancer",
            "selector": {"app": "web"}, "ports": [{"port": 80, "targetPort": 8080}]},
            "status": {"loadBalancer": {"ingress": [{"ip": "8.8.8.8"}]}}}],
        "pod": [{"metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"serviceAccountName": "app", "automountServiceAccountToken": True}}],
        "serviceaccount": [{"metadata": {"name": "app", "namespace": "app"}}],
        "clusterrole": [{"metadata": {"name": "admin"}, "rules": [{"apiGroups": ["*"],
            "resources": ["*"], "verbs": ["*"]}]}],
        "clusterrolebinding": [{"metadata": {"name": "admin"},
            "roleRef": {"kind": "ClusterRole", "name": "admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "app"}]}],
    }, "cluster")
    result = findings(snap)
    assert len(result) == 1 and result[0]["evidence"]["principal"] == "system:serviceaccount:app:app"
    assert_exposure_in_report(snap, monkeypatch)


def test_unrelated_network_policy_does_not_hide_public_privileged_pod():
    snap = snapshot("k8s", {
        "networkpolicy": [{"metadata": {"name": "other", "namespace": "app"},
            "spec": {"podSelector": {"matchLabels": {"app": "other"}}, "policyTypes": ["Ingress"]}}],
        "service": [{"metadata": {"name": "web", "namespace": "app"}, "spec": {"type": "LoadBalancer",
            "selector": {"app": "web"}, "ports": [{"port": 80}]},
            "status": {"loadBalancer": {"ingress": [{"ip": "8.8.8.8"}]}}}],
        "pod": [{"metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
            "spec": {"serviceAccountName": "app", "automountServiceAccountToken": True}}],
        "serviceaccount": [{"metadata": {"name": "app", "namespace": "app"}}],
        "clusterrole": [{"metadata": {"name": "admin"}, "rules": [{"apiGroups": ["*"],
            "resources": ["*"], "verbs": ["*"]}]}],
        "clusterrolebinding": [{"metadata": {"name": "admin"},
            "roleRef": {"kind": "ClusterRole", "name": "admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "app"}]}],
    }, "cluster")
    assert len(findings(snap)) == 1
    policy = next(c for c in snap["collections"] if c["type"] == "networkpolicy")
    policy["items"][0]["spec"]["podSelector"]["matchLabels"] = {"app": "web"}
    assert findings(snap) == []
    policy["items"].append({"metadata": {"name": "allow-all", "namespace": "app"},
        "spec": {"podSelector": {"matchLabels": {"app": "web"}},
            "policyTypes": ["Ingress"], "ingress": [{}]}})
    assert len(findings(snap)) == 1


def test_no_finding_without_both_public_path_and_high_grant():
    snap = snapshot("gcp", {"service_account": [{"email": "app@home.iam.gserviceaccount.com"}],
        "cloudrun_service": [{"name": "web", "uri": "https://web.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL", "invokerIamDisabled": True,
            "template": {"serviceAccount": "app@home.iam.gserviceaccount.com"}}]}, "projects/home")
    assert findings(snap) == []
    snap["collections"].append({"type": "iam_policy", "scope": "projects/home", "service": "iam_policy",
        "status": "collected", "items": [{"bindings": [{"role": "roles/owner",
            "members": ["serviceAccount:app@home.iam.gserviceaccount.com"]}]}]})
    app = next(c for c in snap["collections"] if c["type"] == "cloudrun_service")["items"][0]
    app["ingress"] = "INGRESS_TRAFFIC_INTERNAL_ONLY"
    assert findings(snap) == []


def test_repeated_aws_global_policy_declarations_collapse_only_when_equal():
    base = {"check_id": "analysis.principal_exposure", "provider": "aws", "status": "FAIL",
        "evidence": {"principals": [{"principal": "*", "native_grant": {"Action": "s3:GetObject"},
            "source": {"resource_type": "aws_resource_policy", "resource_id": "arn:aws:s3:::cdn",
                "scope": "111111111111/us-east-1"}}]}}
    first = {**base, "scope": "111111111111/us-east-1"}
    second = {**base, "scope": "111111111111/us-west-2", "evidence": {"principals": [{
        **base["evidence"]["principals"][0], "source": {"resource_type": "aws_resource_policy",
            "resource_id": "arn:aws:s3:::cdn", "scope": "111111111111/us-west-2"}}]}}
    kept = deduplicate_principal_exposure([first, second])
    assert len(kept) == 1
    assert kept[0]["evidence"]["observed_scopes"] == [first["scope"], second["scope"]]
    changed = {**second, "evidence": {"principals": [{**second["evidence"]["principals"][0],
        "native_grant": {"Action": "s3:PutObject"}}]}}
    assert len(deduplicate_principal_exposure([first, changed])) == 2
    different_path = {**second, "evidence": {"principals": [{**second["evidence"]["principals"][0],
        "source": {**second["evidence"]["principals"][0]["source"], "path": "Policy.Statement[1]"}}]}}
    assert len(deduplicate_principal_exposure([first, different_path])) == 2
