terraform {
  required_version = ">= 1.14.3, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
  # Supply deployment-private settings with terraform init -backend-config=PATH.
  backend "s3" {}
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = {
      Application = "hacktricks-cspm"
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}
data "aws_route53_zone" "wiki" {
  name         = "hacktricks.wiki."
  private_zone = false
}
data "aws_acm_certificate" "wiki" {
  domain      = "hacktricks.wiki"
  statuses    = ["ISSUED"]
  most_recent = true
}

locals {
  name         = "hacktricks-cspm"
  domain       = "cspm.hacktricks.wiki"
  account_id   = data.aws_caller_identity.current.account_id
  pool_id      = var.cognito_pool_id
  client_id    = var.cognito_client_id
  issuer       = "https://cognito-idp.us-east-1.amazonaws.com/${local.pool_id}"
  pool_arn     = "arn:aws:cognito-idp:us-east-1:${local.account_id}:userpool/${local.pool_id}"
  stripe_arn   = var.stripe_secret_arn
  stripe_price = var.stripe_price_id
}
