# Backend configuration for remote state management
# Uncomment and configure the appropriate backend for your environment

# S3 Backend (AWS)
/*
terraform {
  backend "s3" {
    bucket         = "your-terraform-state-bucket"
    key            = "vpc/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
  }
}
*/

# Azure Backend
/*
terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-state-rg"
    storage_account_name = "tfstateaccount"
    container_name       = "tfstate"
    key                  = "vpc/terraform.tfstate"
    use_azuread_auth     = true
  }
}
*/

# GCS Backend (Google Cloud)
/*
terraform {
  backend "gcs" {
    bucket = "your-terraform-state-bucket"
    prefix = "vpc/"
    encryption_key = "your-encryption-key"
  }
}
*/

# Local Backend (for development/testing)
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
} 