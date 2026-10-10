locals {
  worker_env = {
    PEASO_STORAGE              = "dynamodb"
    PEASO_DYNAMODB_TABLE       = aws_dynamodb_table.metadata.name
    PEASO_ARTIFACT_BUCKET      = aws_s3_bucket.artifacts.id
    PEASO_SCAN_TIMEOUT_SECONDS = "900"
    PEASO_COLLECTOR_VCPU       = "0.25"
    PEASO_COLLECTOR_MEMORY_GIB = "1"
    PEASO_ANALYZER_VCPU        = "0.5"
    PEASO_ANALYZER_MEMORY_GIB  = "2"
    PEASO_STATE_DIR            = "/tmp/peaso/state"
    PEASO_IDENTITY_DIR         = "/tmp/peaso/identity"
    AWS_DEFAULT_REGION         = var.region
    PEASO_CUSTOMER_ROLE_ARNS   = jsonencode(var.customer_role_arns)
    PEASO_SOURCE_VERSION       = var.source_version
  }
  task_roles = { collector = aws_iam_role.collector.arn, analyzer = aws_iam_role.analyzer.arn }
}
resource "aws_ecs_task_definition" "tasks" {
  for_each                 = local.task_roles
  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.key == "collector" ? "256" : "512"
  memory                   = each.key == "collector" ? "1024" : "2048"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = each.value
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name                   = each.key
    image                  = var.worker_image
    essential              = true
    entryPoint             = ["python", "-m", "peaso.worker"]
    command                = [each.key, "--once"]
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    mountPoints            = [{ sourceVolume = "scratch", containerPath = "/tmp", readOnly = false }]
    linuxParameters        = { capabilities = { drop = ["ALL"] } }
    stopTimeout            = 30
    environment = [for key, value in merge(local.worker_env, {
      PEASO_TASK_VCPU       = each.key == "collector" ? "0.25" : "0.5"
      PEASO_TASK_MEMORY_GIB = each.key == "collector" ? "1" : "2"
      }, each.key == "collector" ? {
      PEASO_CREDENTIAL_SECRET_ARN = aws_secretsmanager_secret.credentials.arn
    } : {}) : { name = key, value = value }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.tasks.name
        awslogs-region        = var.region
        awslogs-stream-prefix = each.key
      }
    }
  }])
  volume { name = "scratch" }
}
locals {
  run_tasks = { for stage in ["collector", "analyzer"] : stage => {
    Type           = "Task"
    Resource       = "arn:aws:states:::ecs:runTask.sync"
    TimeoutSeconds = 900
    Parameters = {
      Cluster         = aws_ecs_cluster.cspm.arn
      TaskDefinition  = aws_ecs_task_definition.tasks[stage].arn
      LaunchType      = "FARGATE"
      PlatformVersion = "1.4.0"
      NetworkConfiguration = {
        AwsvpcConfiguration = {
          Subnets        = [aws_subnet.tasks.id]
          SecurityGroups = [aws_security_group.tasks.id]
          AssignPublicIp = "ENABLED"
        }
      }
      Overrides = {
        ContainerOverrides = [{
          Name        = stage
          "Command.$" = "States.Array('${stage}', '--once', '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)"
        }]
      }
    }
    ResultPath = null
    Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.failure", Next = "ReleaseFailed" }]
    Next       = stage == "collector" ? "ReadCollectedStatus" : "ReadCompletedStatus"
  } }
  release_lock = {
    Type     = "Task"
    Resource = "arn:aws:states:::dynamodb:deleteItem"
    Parameters = {
      TableName                 = aws_dynamodb_table.metadata.name
      Key                       = { PK = { S = "GLOBAL" }, SK = { S = "SCAN_LOCK" } }
      ConditionExpression       = "#owner = :owner"
      ExpressionAttributeNames  = { "#owner" = "owner" }
      ExpressionAttributeValues = { ":owner" = { "S.$" = "$$.Execution.Id" } }
    }
    ResultPath = null
    Retry      = [{ ErrorEquals = ["DynamoDB.ProvisionedThroughputExceededException", "DynamoDB.InternalServerError"], IntervalSeconds = 2, MaxAttempts = 3 }]
  }
  read_job_status = {
    Type     = "Task"
    Resource = "arn:aws:states:::dynamodb:getItem"
    Parameters = {
      TableName                = aws_dynamodb_table.metadata.name
      Key                      = { PK = { "S.$" = "States.Format('tenant/{}', $.tenant_id)" }, SK = { "S.$" = "States.Format('job/{}', $.scan_id)" } }
      ConsistentRead           = true
      ProjectionExpression     = "#status"
      ExpressionAttributeNames = { "#status" = "status" }
    }
    ResultPath = "$.job_status"
    Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.failure", Next = "ReleaseFailed" }]
  }
  mark_failed = {
    Type          = "Task"
    Resource      = "arn:aws:states:::dynamodb:updateItem"
    QueryLanguage = "JSONata"
    Arguments = {
      TableName                = aws_dynamodb_table.metadata.name
      Key                      = { PK = { S = "{% 'tenant/' & $states.input.tenant_id %}" }, SK = { S = "{% 'job/' & $states.input.scan_id %}" } }
      UpdateExpression         = "SET #status=:failed, #owner=:null, lease=:null, #error=:error, error_code=:code, error_stage=:stage, #history=list_append(if_not_exists(#history,:empty),:event) ADD #rev :one"
      ConditionExpression      = "attribute_exists(PK) AND #status IN (:queued,:collecting,:collected,:analyzing)"
      ExpressionAttributeNames = { "#status" = "status", "#owner" = "owner", "#error" = "error", "#history" = "history", "#rev" = "rev" }
      ExpressionAttributeValues = {
        ":failed" = { S = "failed" }, ":null" = { NULL = true }, ":one" = { N = "1" }
        ":error"  = { S = "Hosted workflow did not complete; retry after checking connector access" }
        ":code"   = { S = "workflow_failed" }, ":stage" = { S = "workflow" }
        ":queued" = { S = "queued" }, ":collecting" = { S = "collecting" }, ":collected" = { S = "collected" }, ":analyzing" = { S = "analyzing" }
        ":empty"  = { L = [] }, ":event" = { L = [{ M = { status = { S = "failed" }, at = { S = "{% $now() %}" } } }] }
      }
    }
    Output = "{% $states.input %}"
    Catch  = [{ ErrorEquals = ["DynamoDB.ConditionalCheckFailedException"], Next = "Failed" }]
    Next   = "Failed"
  }
}
resource "aws_sfn_state_machine" "scan" {
  name     = local.name
  role_arn = aws_iam_role.workflow.arn
  type     = "STANDARD"
  definition = jsonencode({
    Comment        = "One bounded cloud collector followed by an offline analyzer with separate credentials"
    StartAt        = "AcquireSlot"
    TimeoutSeconds = 1800
    States = {
      AcquireSlot = {
        Type          = "Task", Resource = "arn:aws:states:::dynamodb:putItem"
        QueryLanguage = "JSONata"
        Arguments = {
          TableName = aws_dynamodb_table.metadata.name
          Item = {
            PK         = { S = "GLOBAL" }, SK = { S = "SCAN_LOCK" }
            owner      = { S = "{% $states.context.Execution.Id %}" }
            expires_at = { N = "{% $string($floor($millis() / 1000) + 2100) %}" }
          }
          ConditionExpression       = "attribute_not_exists(PK) OR expires_at < :now"
          ExpressionAttributeValues = { ":now" = { N = "{% $string($floor($millis() / 1000)) %}" } }
        }
        Output = "{% $states.input %}"
        Retry  = [{ ErrorEquals = ["DynamoDB.ConditionalCheckFailedException"], IntervalSeconds = 60, BackoffRate = 1, MaxAttempts = 5 }]
        Catch  = [{ ErrorEquals = ["States.ALL"], Output = "{% $states.input %}", Next = "MarkFailed" }]
        Next   = "Collect"
      }
      Collect             = local.run_tasks.collector
      Analyze             = local.run_tasks.analyzer
      ReadCollectedStatus = merge(local.read_job_status, { Next = "CollectedStatus" })
      CollectedStatus = {
        Type    = "Choice"
        Choices = [{ Variable = "$.job_status.Item.status.S", StringEquals = "collected", Next = "Analyze" }]
        Default = "ReleaseFailed"
      }
      ReadCompletedStatus = merge(local.read_job_status, { Next = "CompletedStatus" })
      CompletedStatus = {
        Type    = "Choice"
        Choices = [{ Variable = "$.job_status.Item.status.S", StringEquals = "completed", Next = "ReleaseSucceeded" }]
        Default = "ReleaseFailed"
      }
      ReleaseSucceeded = merge(local.release_lock, { Next = "Succeeded" })
      ReleaseFailed    = merge(local.release_lock, { Next = "MarkFailed" })
      MarkFailed       = local.mark_failed
      Succeeded        = { Type = "Succeed" }
      Failed           = { Type = "Fail", Error = "ScanTaskFailed", Cause = "The bounded scan did not complete" }
    }
  })
  depends_on = [aws_iam_role_policy.workflow, aws_iam_role_policy.execution, aws_iam_role_policy.collector, aws_iam_role_policy.analyzer, aws_route_table_association.tasks]
}
