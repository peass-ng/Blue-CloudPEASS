resource "aws_s3_bucket" "frontend" {
  bucket = "${local.name}-frontend-${local.account_id}"
}
resource "aws_s3_object" "customer_role_download" {
  bucket              = aws_s3_bucket.frontend.id
  key                 = "aws/customer-role.json"
  source              = "${path.module}/customer-role.json"
  etag                = filemd5("${path.module}/customer-role.json")
  content_type        = "application/json"
  content_disposition = "attachment; filename=\"customer-role.json\""
}
resource "aws_s3_bucket" "templates" {
  count  = var.enable_public_customer_role_template ? 1 : 0
  bucket = "${local.name}-templates-${local.account_id}"
}
locals {
  customer_role_template_sha256 = filesha256("${path.module}/customer-role.json")
  customer_role_template_key    = "customer-role-${local.customer_role_template_sha256}.json"
  customer_role_template_sources = merge(
    var.archived_customer_role_templates,
    { (local.customer_role_template_sha256) = "${path.module}/customer-role.json" }
  )
}
resource "aws_s3_bucket_versioning" "templates" {
  count  = var.enable_public_customer_role_template ? 1 : 0
  bucket = aws_s3_bucket.templates[0].id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_ownership_controls" "templates" {
  count  = var.enable_public_customer_role_template ? 1 : 0
  bucket = aws_s3_bucket.templates[0].id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "templates" {
  count  = var.enable_public_customer_role_template ? 1 : 0
  bucket = aws_s3_bucket.templates[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "templates" {
  count                   = var.enable_public_customer_role_template ? 1 : 0
  bucket                  = aws_s3_bucket.templates[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}
resource "aws_s3_object" "customer_role_template" {
  for_each            = var.enable_public_customer_role_template ? local.customer_role_template_sources : {}
  bucket              = aws_s3_bucket.templates[0].id
  key                 = "customer-role-${each.key}.json"
  source              = each.value
  etag                = filemd5(each.value)
  content_type        = "application/json"
  content_disposition = "attachment; filename=\"customer-role.json\""
  cache_control       = "public,max-age=31536000,immutable"
  metadata            = { sha256 = each.key }
  depends_on          = [aws_s3_bucket_versioning.templates]
  lifecycle {
    ignore_changes = [source]
    precondition {
      condition     = filesha256(each.value) == each.key
      error_message = "Customer-role version file must match its immutable SHA256 object key"
    }
  }
}
moved {
  from = aws_s3_object.customer_role_template[0]
  to   = aws_s3_object.customer_role_template["d7f7b815628bb270f4bd40f985d70de7ba1bbd50cefa4f429031ea0a74e08bcd"]
}
resource "aws_s3_bucket_policy" "templates" {
  count  = var.enable_public_customer_role_template ? 1 : 0
  bucket = aws_s3_bucket.templates[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "PublicReadOnlyCustomerRoleTemplate", Effect = "Allow", Principal = "*", Action = "s3:GetObject",
    Resource = aws_s3_object.customer_role_template[local.customer_role_template_sha256].arn },
    { Sid      = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource = [aws_s3_bucket.templates[0].arn, "${aws_s3_bucket.templates[0].arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } } }
  ] })
  depends_on = [aws_s3_bucket_public_access_block.templates]
}
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name}-artifacts-${local.account_id}"
}
resource "aws_s3_object" "api_zip" {
  bucket                 = aws_s3_bucket.artifacts.id
  key                    = "runtime-packages/${filesha256(var.api_zip)}.zip"
  source                 = var.api_zip
  source_hash            = filebase64sha256(var.api_zip)
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.connectors.arn
  metadata               = { sha256 = filesha256(var.api_zip) }
}
locals {
  buckets = { frontend = aws_s3_bucket.frontend.id, artifacts = aws_s3_bucket.artifacts.id }
}
resource "aws_s3_bucket_public_access_block" "private" {
  for_each                = local.buckets
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "private" {
  for_each = local.buckets
  bucket   = each.value
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "private" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "expire-bounded-artifacts"
    status = "Enabled"
    filter {}
    expiration { days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  rule {
    id     = "expire-customer-credential-inputs"
    status = "Enabled"
    filter { prefix = "inputs/" }
    expiration { days = 1 }
  }
}
resource "aws_s3_bucket_cors_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  cors_rule {
    allowed_origins = ["https://${local.domain}"]
    allowed_methods = ["GET", "HEAD"]
    allowed_headers = ["*"]
    expose_headers  = ["ETag", "Content-Length", "Content-Disposition"]
    max_age_seconds = 300
  }
}
resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.artifacts.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*",
    Resource  = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_dynamodb_table" "metadata" {
  name         = local.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"
  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }
  attribute {
    name = "status"
    type = "S"
  }
  attribute {
    name = "created"
    type = "N"
  }
  attribute {
    name = "kind"
    type = "S"
  }
  attribute {
    name = "next_run"
    type = "N"
  }
  global_secondary_index {
    name            = "work-state"
    hash_key        = "status"
    range_key       = "created"
    projection_type = "KEYS_ONLY"
  }
  global_secondary_index {
    name            = "schedule-time"
    hash_key        = "kind"
    range_key       = "next_run"
    projection_type = "KEYS_ONLY"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}
resource "aws_ecr_repository" "worker" {
  name                 = "${local.name}-worker"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}
resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name
  policy = jsonencode({ rules = [{
    rulePriority = 1, description = "Keep three immutable worker releases",
    selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 3 },
    action       = { type = "expire" }
  }] })
}
resource "aws_kms_key" "connectors" {
  description             = "CSPM connector envelope encryption; analyzer cannot decrypt"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}
resource "aws_kms_alias" "connectors" {
  name          = "alias/${local.name}-connectors"
  target_key_id = aws_kms_key.connectors.key_id
}
resource "random_bytes" "credential_key" { length = 32 }
resource "aws_secretsmanager_secret" "credentials" {
  name                    = "${local.name}-credential-key"
  kms_key_id              = aws_kms_key.connectors.arn
  recovery_window_in_days = 30
}
resource "aws_secretsmanager_secret_version" "credentials" {
  secret_id     = aws_secretsmanager_secret.credentials.id
  secret_string = random_bytes.credential_key.base64
}

# Separate from connector encryption: AI can use captured sessions but cannot
# decrypt source connector credentials or the platform service-account key.
resource "random_bytes" "ai_key" { length = 32 }
resource "aws_kms_key" "ai" {
  description             = "CSPM AI session and personal Codex envelope encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}
resource "aws_secretsmanager_secret" "ai" {
  name                    = "${local.name}-ai-key"
  kms_key_id              = aws_kms_key.ai.arn
  recovery_window_in_days = 30
}
resource "aws_secretsmanager_secret_version" "ai" {
  secret_id     = aws_secretsmanager_secret.ai.id
  secret_string = random_bytes.ai_key.base64
}
