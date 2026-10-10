locals {
  lambda_trust = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
  task_trust = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = {
      StringEquals = { "aws:SourceAccount" = local.account_id }
      ArnLike      = { "aws:SourceArn" = "arn:aws:ecs:${var.region}:${local.account_id}:*" }
    }
  }] })
  workflow_arn = "arn:aws:states:${var.region}:${local.account_id}:stateMachine:${local.name}"
}
resource "aws_iam_role" "api" {
  name               = "${local.name}-api"
  assume_role_policy = local.lambda_trust
}
resource "aws_iam_role_policy" "api" {
  role = aws_iam_role.api.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["${aws_cloudwatch_log_group.api.arn}:*", "${aws_cloudwatch_log_group.scheduler.arn}:*"] },
    { Effect = "Allow", Action = ["dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:TransactWriteItems"], Resource = aws_dynamodb_table.metadata.arn },
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${aws_s3_bucket.artifacts.arn}/*" },
    { Effect = "Allow", Action = ["cognito-idp:AdminGetUser", "cognito-idp:DescribeUserPoolClient"], Resource = local.pool_arn },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.credentials.arn, local.stripe_arn] },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.connectors.arn },
    { Effect = "Allow", Action = ["states:StartExecution"], Resource = local.workflow_arn },
    { Effect = "Allow", Action = ["states:DescribeExecution"], Resource = "arn:aws:states:${var.region}:${local.account_id}:execution:${local.name}:*" }
  ] })
}
resource "aws_iam_role" "execution" {
  name               = "${local.name}-task-execution"
  assume_role_policy = local.task_trust
}
resource "aws_iam_role_policy" "execution" {
  role = aws_iam_role.execution.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource = aws_ecr_repository.worker.arn },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.tasks.arn}:*" }
  ] })
}
resource "aws_iam_role" "collector" {
  name               = "${local.name}-collector"
  assume_role_policy = local.task_trust
}
resource "aws_iam_role_policy" "collector" {
  role = aws_iam_role.collector.id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([
    { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:Query"], Resource = aws_dynamodb_table.metadata.arn },
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${aws_s3_bucket.artifacts.arn}/*" },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.credentials.arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.connectors.arn }
    ], length(var.customer_role_arns) == 0 ? [] : [{
      Effect    = "Allow", Action = ["sts:AssumeRole"], Resource = var.customer_role_arns,
      Condition = { StringLike = { "sts:ExternalId" = "peaso-*" } }
  }]) })
}
resource "aws_iam_role" "analyzer" {
  name               = "${local.name}-analyzer"
  assume_role_policy = local.task_trust
}
resource "aws_iam_role_policy" "analyzer" {
  role = aws_iam_role.analyzer.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:Query"], Resource = aws_dynamodb_table.metadata.arn },
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${aws_s3_bucket.artifacts.arn}/*" },
    # Explicit deny prevents future shared permissions from exposing cloud credentials.
    { Effect = "Deny", Action = ["sts:AssumeRole", "secretsmanager:GetSecretValue", "kms:Decrypt"], Resource = "*" }
  ] })
}
resource "aws_iam_role" "workflow" {
  name = "${local.name}-workflow"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Principal = { Service = "states.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = { StringEquals = { "aws:SourceAccount" = local.account_id }, ArnEquals = { "aws:SourceArn" = local.workflow_arn } }
  }] })
}
resource "aws_iam_role_policy" "workflow" {
  role = aws_iam_role.workflow.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecs:RunTask"], Resource = [for task in aws_ecs_task_definition.tasks : task.arn], Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.cspm.arn } } },
    { Effect = "Allow", Action = ["ecs:StopTask", "ecs:DescribeTasks"], Resource = "arn:aws:ecs:${var.region}:${local.account_id}:task/${aws_ecs_cluster.cspm.name}/*", Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.cspm.arn } } },
    { Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.execution.arn, aws_iam_role.collector.arn, aws_iam_role.analyzer.arn], Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } } },
    { Effect = "Allow", Action = ["events:PutTargets", "events:PutRule", "events:DescribeRule"], Resource = "arn:aws:events:${var.region}:${local.account_id}:rule/StepFunctionsGetEventsForECSTaskRule" },
    { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"], Resource = aws_dynamodb_table.metadata.arn }
  ] })
}
