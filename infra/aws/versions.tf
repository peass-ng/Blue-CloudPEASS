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
  # Isolated state: never reuse the existing wiki/terraform.tfstate key.
  backend "s3" {
    bucket       = "terraform-state-hacktricks-wiki"
    key          = "cspm/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = ["202533532952"]
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
  pool_id      = "us-east-1_7rbhezdKX"
  client_id    = "3g2u5ilb7kbte92lra40ji2ht0"
  issuer       = "https://cognito-idp.us-east-1.amazonaws.com/${local.pool_id}"
  pool_arn     = "arn:aws:cognito-idp:us-east-1:${local.account_id}:userpool/${local.pool_id}"
  stripe_arn   = "arn:aws:secretsmanager:us-east-1:202533532952:secret:hacktricks-tools-stripe-secret-key-zoewPl"
  stripe_price = "price_1TLm63Io7pPswHK23F4vZFvW"
}
