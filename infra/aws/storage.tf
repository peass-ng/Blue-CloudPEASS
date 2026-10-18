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
    { "d7f7b815628bb270f4bd40f985d70de7ba1bbd50cefa4f429031ea0a74e08bcd" = "${path.module}/customer-role-d7f7b815628bb270f4bd40f985d70de7ba1bbd50cefa4f429031ea0a74e08bcd.json" },
    { "7e6fc610eee9021025ffd498c8dc924d740975a34c56f291bc7317a7db182dbe" = "${path.module}/customer-role-7e6fc610eee9021025ffd498c8dc924d740975a34c56f291bc7317a7db182dbe.json" },
    { "04fbe795580c205cb86e6ad71a73c52935628bd43c5d5ee398b4333b2155748a" = "${path.module}/customer-role-04fbe795580c205cb86e6ad71a73c52935628bd43c5d5ee398b4333b2155748a.json" },
    { "25b895c00a3fad47f390e4946c83f6e47487c8e52e8342cf136d1a1eb1c1ea17" = "${path.module}/customer-role-25b895c00a3fad47f390e4946c83f6e47487c8e52e8342cf136d1a1eb1c1ea17.json" },
    { "9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f" = "${path.module}/customer-role-9254e0c0c0a7519c7a0a0c128e9d147d799dba3ca9cf9ff76902fcb4cd5ab08f.json" },
    { "ccd97a3b24443ee6556e59f23ab0d3bf42b7b2013481047b5c586932d0570c14" = "${path.module}/customer-role-ccd97a3b24443ee6556e59f23ab0d3bf42b7b2013481047b5c586932d0570c14.json" },
    { "6d31b087d5542e740af07fa1e05ede2c7faca0b712ffdb8dba43c19d2cb2ce21" = "${path.module}/customer-role-6d31b087d5542e740af07fa1e05ede2c7faca0b712ffdb8dba43c19d2cb2ce21.json" },
    { "95e70cc9e033643bb3d7e0a400246f7ee392c5d3301319027482bc4350c09a25" = "${path.module}/customer-role-95e70cc9e033643bb3d7e0a400246f7ee392c5d3301319027482bc4350c09a25.json" },
    { "e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d" = "${path.module}/customer-role-e2b8788e174bba78779421bb13b2c5d12ae1dd2599715653e7ea62f4463bcc0d.json" },
    { "f46db717efb93db136ec5893e819904b0fb931f4ba512f52d6cdb907a6e6a04c" = "${path.module}/customer-role-f46db717efb93db136ec5893e819904b0fb931f4ba512f52d6cdb907a6e6a04c.json" },
    { "2204d577d48f10958947199b840d0989b88bbeee4e4b396193cc427b59f39ccf" = "${path.module}/customer-role-2204d577d48f10958947199b840d0989b88bbeee4e4b396193cc427b59f39ccf.json" },
    { "a57cdf166f64c9ad96a367a48fb62e54754a58a89ed767119f9dc46c05e46980" = "${path.module}/customer-role-a57cdf166f64c9ad96a367a48fb62e54754a58a89ed767119f9dc46c05e46980.json" },
    { "2b6825b57ea8d5a443b35e5fda86bc97eda6324721dcfd002b52a8cf356cd92f" = "${path.module}/customer-role-2b6825b57ea8d5a443b35e5fda86bc97eda6324721dcfd002b52a8cf356cd92f.json" },
    { "7da8ecb219db8799e87cab5b4a632f6d40c7e4d6f5cb5c4cd1eea1a6fbdd2fe6" = "${path.module}/customer-role-7da8ecb219db8799e87cab5b4a632f6d40c7e4d6f5cb5c4cd1eea1a6fbdd2fe6.json" },
    { "a4c004efe171a0c94977fefc31fbc30c0d879b7c4e98875862aa498aa4d7a873" = "${path.module}/customer-role-a4c004efe171a0c94977fefc31fbc30c0d879b7c4e98875862aa498aa4d7a873.json" },
    { "0484deedf711ac855f691e08531561c5b29abff7e46fa16320b79a32465eb6b2" = "${path.module}/customer-role-0484deedf711ac855f691e08531561c5b29abff7e46fa16320b79a32465eb6b2.json" },
    { "fef2efcc028af51f48a4fa6d883b4ce959dba3691b0b9de3872971a9aac94c82" = "${path.module}/customer-role-fef2efcc028af51f48a4fa6d883b4ce959dba3691b0b9de3872971a9aac94c82.json" },
    { "3e692bf06dc4af76517d6838f28fc5bcdbd890fd2029045b33a2262570cf13ee" = "${path.module}/customer-role-3e692bf06dc4af76517d6838f28fc5bcdbd890fd2029045b33a2262570cf13ee.json" },
    { "1d8b49e45753dc7cba7069d772ad5286b5d033b294dacf6bea3a4ffd1c2aa2b1" = "${path.module}/customer-role-1d8b49e45753dc7cba7069d772ad5286b5d033b294dacf6bea3a4ffd1c2aa2b1.json" },
    { "96369f6236d3d2d803c75f8c982e9828c6ce5eda4697d5c39f91451478350cb2" = "${path.module}/customer-role-96369f6236d3d2d803c75f8c982e9828c6ce5eda4697d5c39f91451478350cb2.json" },
    { "c6549e16bbd36c1a7bd66aaf2a620906832097af64b244e6d999d456c594baed" = "${path.module}/customer-role-c6549e16bbd36c1a7bd66aaf2a620906832097af64b244e6d999d456c594baed.json" },
    { "4ea77d8e8f9ec707db8536313086cac740a37083280085054de0cf93b8420794" = "${path.module}/customer-role-4ea77d8e8f9ec707db8536313086cac740a37083280085054de0cf93b8420794.json" },
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
    Resource = [for object in aws_s3_object.customer_role_template : object.arn] },
    { Sid      = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource = [aws_s3_bucket.templates[0].arn, "${aws_s3_bucket.templates[0].arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } } }
  ] })
  depends_on = [aws_s3_bucket_public_access_block.templates]
}
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name}-artifacts-${local.account_id}"
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
