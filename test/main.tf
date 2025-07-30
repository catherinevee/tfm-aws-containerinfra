# ==============================================================================
# Container Infrastructure Module Test Configuration
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
# Test Container Infrastructure Module
# ==============================================================================

module "container_infrastructure_test" {
  source = "../"

  name        = "test-infra"
  environment = "test"

  # VPC Configuration
  vpc_config = {
    cidr_block = "10.1.0.0/16"
    enable_nat_gateway = true
    single_nat_gateway = true  # Cost optimization for testing
    enable_dns_hostnames = true
    enable_dns_support   = true
    enable_flow_log = true
    flow_log_retention_in_days = 7
  }

  # Subnet Configuration
  subnet_config = {
    azs             = ["us-west-2a", "us-west-2b"]
    private_subnets = ["10.1.1.0/24", "10.1.2.0/24"]
    public_subnets  = ["10.1.101.0/24", "10.1.102.0/24"]
  }

  # EKS Configuration
  eks_config = {
    cluster_version = "1.28"
    cluster_endpoint_private_access = true
    cluster_endpoint_public_access  = true
    cluster_endpoint_public_access_cidrs = ["10.1.0.0/16"]
    cluster_service_ipv4_cidr = "172.16.0.0/12"
    enable_irsa = true
    enable_cluster_creator_admin_permissions = true
    create_cloudwatch_log_group = true
    cluster_log_retention_in_days = 7
    cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  }

  # EKS Node Groups
  eks_node_groups = {
    test = {
      name           = "test"
      instance_types = ["t3.small"]
      capacity_type  = "ON_DEMAND"
      desired_size   = 1
      max_size       = 2
      min_size       = 1
      disk_size      = 20
      disk_type      = "gp3"
      labels = {
        node-type = "test"
        environment = "test"
      }
    }
  }

  # ECR Repositories
  ecr_repositories = {
    test-app = {
      name = "test-app"
      image_tag_mutability = "MUTABLE"
      scan_on_push = true
      encryption_type = "AES256"
      lifecycle_policy = {
        max_image_count = 10
        max_age_days    = 30
      }
      tags = {
        Purpose = "testing"
      }
    }
  }

  # ECR Pull Through Cache Rules
  ecr_pull_through_cache_rules = {
    docker_hub = {
      repository_prefix = "docker.io"
      upstream_registry_url = "https://registry-1.docker.io"
      tags = {
        Purpose = "testing"
      }
    }
  }

  # Security Groups
  security_groups = {
    test-app = {
      name = "test-app"
      description = "Security group for test application"
      ingress_rules = [
        {
          description = "HTTP from VPC"
          from_port   = 80
          to_port     = 80
          protocol    = "tcp"
          cidr_blocks = ["10.1.0.0/16"]
        }
      ]
    }
  }

  # Monitoring and Observability (Limited for testing)
  enable_cloudwatch_container_insights = true
  enable_aws_load_balancer_controller = true
  enable_metrics_server = true
  enable_cluster_autoscaler = false  # Disabled for testing to reduce costs
  
  # Prometheus Monitoring (Disabled for testing to reduce costs)
  enable_prometheus_monitoring = false
  
  # Kubernetes Dashboard (Disabled for testing)
  enable_kubernetes_dashboard = false
  
  # Jaeger Tracing (Disabled for testing)
  enable_jaeger_tracing = false
  
  # Network Policies (Disabled for testing)
  enable_network_policies = false
  
  # Backup and Disaster Recovery (Disabled for testing)
  enable_velero_backup = false

  # Common Tags
  tags = {
    Project     = "terraform-testing"
    Environment = "test"
    Owner       = "test-team"
    Purpose     = "module-validation"
  }
} 