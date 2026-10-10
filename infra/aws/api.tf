locals {
  runtime_env = {
    PEASO_AUTH_MODE             = "cognito"
    PEASO_COGNITO_ISSUER        = local.issuer
    PEASO_COGNITO_CLIENT_ID     = local.client_id
    PEASO_STORAGE               = "dynamodb"
    PEASO_DYNAMODB_TABLE        = aws_dynamodb_table.metadata.name
    PEASO_ARTIFACT_BUCKET       = aws_s3_bucket.artifacts.id
    PEASO_CREDENTIAL_SECRET_ARN = aws_secretsmanager_secret.credentials.arn
    PEASO_STRIPE_SECRET_ARN     = local.stripe_arn
    PEASO_STRIPE_PRICE_ID       = local.stripe_price
    PEASO_WORKFLOW_ARN          = local.workflow_arn
    PEASO_ALLOWED_ORIGINS       = "https://${local.domain}"
    PEASO_CUSTOMER_ROLE_ARNS    = jsonencode(var.customer_role_arns)
    PEASO_SOURCE_VERSION        = var.source_version
    PEASO_SOURCE_URL            = "https://${local.domain}/source/peaso-source-${var.source_version}.zip"
    PEASO_SCAN_TIMEOUT_SECONDS  = "900"
    PEASO_COLLECTOR_VCPU        = "0.25"
    PEASO_COLLECTOR_MEMORY_GIB  = "1"
    PEASO_ANALYZER_VCPU         = "0.5"
    PEASO_ANALYZER_MEMORY_GIB   = "2"
    PEASO_STATE_DIR             = "/tmp/peaso/state"
    PEASO_IDENTITY_DIR          = "/tmp/peaso/identity"
  }
}
resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/${local.name}-api"
  retention_in_days = 7
}
resource "aws_cloudwatch_log_group" "scheduler" {
  name              = "/aws/lambda/${local.name}-scheduler"
  retention_in_days = 7
}
resource "aws_lambda_function" "api" {
  function_name                  = "${local.name}-api"
  role                           = aws_iam_role.api.arn
  runtime                        = "python3.12"
  architectures                  = ["x86_64"]
  handler                        = "peaso.server.lambda_handler.handler"
  filename                       = var.api_zip
  source_code_hash               = filebase64sha256(var.api_zip)
  memory_size                    = 512
  timeout                        = 28
  reserved_concurrent_executions = 3
  environment { variables = local.runtime_env }
  depends_on = [aws_iam_role_policy.api, aws_cloudwatch_log_group.api, aws_secretsmanager_secret_version.credentials]
}
resource "aws_lambda_function" "scheduler" {
  function_name                  = "${local.name}-scheduler"
  role                           = aws_iam_role.api.arn
  runtime                        = "python3.12"
  architectures                  = ["x86_64"]
  handler                        = "peaso.server.scheduler_handler.handler"
  filename                       = var.api_zip
  source_code_hash               = filebase64sha256(var.api_zip)
  memory_size                    = 256
  timeout                        = 60
  reserved_concurrent_executions = 1
  environment { variables = local.runtime_env }
  depends_on = [aws_iam_role_policy.api, aws_cloudwatch_log_group.scheduler, aws_secretsmanager_secret_version.credentials]
}
resource "aws_apigatewayv2_api" "cspm" {
  name          = local.name
  protocol_type = "HTTP"
}
resource "aws_apigatewayv2_integration" "api" {
  api_id                 = aws_apigatewayv2_api.cspm.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}
resource "aws_apigatewayv2_route" "api" {
  api_id    = aws_apigatewayv2_api.cspm.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.api.id}"
}
resource "aws_apigatewayv2_stage" "api" {
  api_id      = aws_apigatewayv2_api.cspm.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }
}
resource "aws_lambda_permission" "api" {
  statement_id  = "CspmHttpApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.cspm.execution_arn}/*/*"
}
resource "aws_cloudwatch_event_rule" "schedules" {
  name                = "${local.name}-schedules"
  schedule_expression = "rate(15 minutes)"
}
resource "aws_cloudwatch_event_target" "schedules" {
  rule = aws_cloudwatch_event_rule.schedules.name
  arn  = aws_lambda_function.scheduler.arn
}
resource "aws_lambda_permission" "schedules" {
  statement_id  = "CspmScheduleTick"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scheduler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedules.arn
}
