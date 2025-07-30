# ==============================================================================
# Basic Container Infrastructure Example
# ==============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# ==============================================================================
# Container Infrastructure Module
# ==============================================================================

module "container_infrastructure" {
  source = "../../"

  name        = "my-app"
  environment = "dev"

  # VPC Configuration
  vpc_config = {
    cidr_block = "10.0.0.0/16"
    enable_nat_gateway = true
    single_nat_gateway = true  # Cost optimization for dev environment
    enable_dns_hostnames = true
    enable_dns_support   = true
  }

  # Subnet Configuration
  subnet_config = {
    azs             = ["us-west-2a", "us-west-2b"]
    private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
    public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
  }

  # EKS Configuration
  eks_node_groups = {
    general = {
      name           = "general"
      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
      desired_size   = 2
      max_size       = 4
      min_size       = 1
      disk_size      = 20
      disk_type      = "gp3"
      labels = {
        node-type = "general"
        environment = "dev"
      }
    }
  }

  # ECR Repositories
  ecr_repositories = {
    app = {
      name = "my-app"
      image_tag_mutability = "MUTABLE"
      scan_on_push = true
      encryption_type = "AES256"
      lifecycle_policy = {
        max_image_count = 30
        max_age_days    = 90
      }
    }
  }

  # Security Groups
  security_groups = {
    app = {
      name = "app"
      description = "Security group for application pods"
      ingress_rules = [
        {
          description = "HTTP from ALB"
          from_port   = 80
          to_port     = 80
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/16"]
        },
        {
          description = "HTTPS from ALB"
          from_port   = 443
          to_port     = 443
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/16"]
        }
      ]
    }
  }

  # Enable basic monitoring and features
  enable_cloudwatch_container_insights = true
  enable_aws_load_balancer_controller = true
  enable_metrics_server = true

  # Common tags
  tags = {
    Project     = "my-app"
    Environment = "dev"
    Owner       = "devops-team"
    CostCenter  = "engineering"
  }
} 