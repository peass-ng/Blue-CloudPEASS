variable "region" {
  type    = string
  default = "us-east-1"
  validation {
    condition     = var.region == "us-east-1"
    error_message = "The existing wiki identity and CloudFront certificate are in us-east-1."
  }
}
variable "api_zip" {
  type        = string
  description = "Absolute path to the built Linux x86_64 FastAPI/Mangum ZIP."
}
variable "source_version" {
  type        = string
  default     = "unreleased"
  description = "SHA256 manifest of the exact frozen source used to build the release."
  validation {
    condition     = var.source_version == "unreleased" || can(regex("^[a-f0-9]{64}$", var.source_version))
    error_message = "Release source version must be a SHA256 manifest digest."
  }
}
variable "worker_image" {
  type        = string
  description = "Published CSPM-only collector/analyzer image pinned by sha256 digest."
  validation {
    condition     = can(regex("^202533532952\\.dkr\\.ecr\\.us-east-1\\.amazonaws\\.com/hacktricks-cspm-worker@sha256:[a-f0-9]{64}$", var.worker_image))
    error_message = "Use the dedicated wiki-account ECR repository and an immutable digest."
  }
}
variable "customer_role_arns" {
  type        = list(string)
  default     = []
  description = "Explicitly onboarded customer read-only role ARNs. Empty disables cross-account collection."
  validation {
    condition     = alltrue([for arn in var.customer_role_arns : can(regex("^arn:aws:iam::[0-9]{12}:role/.+", arn))])
    error_message = "Each approved customer role must be an IAM role ARN."
  }
}
variable "budget_email" {
  type        = string
  description = "Address receiving CSPM budget alerts."
  default     = "carlospolop@gmail.com"
}
variable "monthly_budget_usd" {
  type    = number
  default = 25
  validation {
    condition     = var.monthly_budget_usd >= 1 && var.monthly_budget_usd <= 100
    error_message = "Keep the dedicated CSPM monthly budget within $1-$100."
  }
}
