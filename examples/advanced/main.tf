# ==============================================================================
# Advanced Container Infrastructure Example
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
# Advanced Container Infrastructure Module
# ==============================================================================

module "container_infrastructure" {
  source = "../../"

  name        = "enterprise-app"
  environment = "prod"

  # VPC Configuration
  vpc_config = {
    cidr_block = "10.0.0.0/16"
    enable_nat_gateway = true
    single_nat_gateway = false
    enable_flow_log = true
    flow_log_retention_in_days = 30
    enable_dns_hostnames = true
    enable_dns_support   = true
  }

  # Subnet Configuration
  subnet_config = {
    azs             = ["us-west-2a", "us-west-2b", "us-west-2c"]
    private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
    database_subnets = ["10.0.201.0/24", "10.0.202.0/24", "10.0.203.0/24"]
  }

  # EKS Configuration
  eks_config = {
    cluster_version = "1.28"
    cluster_endpoint_private_access = true
    cluster_endpoint_public_access  = true
    cluster_endpoint_public_access_cidrs = ["10.0.0.0/16", "192.168.0.0/16"]
    cluster_service_ipv4_cidr = "172.16.0.0/12"
    enable_irsa = true
    enable_cluster_creator_admin_permissions = true
    create_cloudwatch_log_group = true
    cluster_log_retention_in_days = 30
    cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  }

  # EKS Node Groups
  eks_node_groups = {
    general = {
      name           = "general"
      instance_types = ["t3.medium", "t3.large"]
      capacity_type  = "ON_DEMAND"
      desired_size   = 3
      max_size       = 10
      min_size       = 1
      disk_size      = 50
      disk_type      = "gp3"
      labels = {
        node-type = "general"
        environment = "prod"
      }
      taints = []
    }
    
    spot = {
      name           = "spot"
      instance_types = ["t3.medium", "t3.large", "m5.large"]
      capacity_type  = "SPOT"
      desired_size   = 2
      max_size       = 8
      min_size       = 0
      disk_size      = 50
      disk_type      = "gp3"
      labels = {
        node-type = "spot"
        environment = "prod"
      }
      taints = [
        {
          key    = "spot"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      ]
    }
  }

  # EKS Fargate Profiles
  eks_fargate_profiles = {
    default = {
      name = "default"
      selectors = [
        {
          namespace = "default"
          labels = {
            fargate = "true"
          }
        },
        {
          namespace = "kube-system"
        }
      ]
    }
  }

  # ECR Repositories with Enhanced Features
  ecr_repositories = {
    app = {
      name = "enterprise-app"
      image_tag_mutability = "IMMUTABLE"
      scan_on_push = true
      encryption_type = "KMS"
      lifecycle_policy = {
        max_image_count = 50
        max_age_days    = 180
      }
      cross_account_access = {
        account_ids = ["123456789012", "987654321098"]
        organization_id = "o-abcdef123456"
      }
      tags = {
        Application = "enterprise-app"
        Component   = "backend"
      }
    }
    
    frontend = {
      name = "enterprise-frontend"
      image_tag_mutability = "IMMUTABLE"
      scan_on_push = true
      encryption_type = "KMS"
      lifecycle_policy = {
        max_image_count = 30
        max_age_days    = 90
      }
      tags = {
        Application = "enterprise-app"
        Component   = "frontend"
      }
    }
  }

  # ECR Pull Through Cache Rules
  ecr_pull_through_cache_rules = {
    docker_hub = {
      repository_prefix = "docker.io"
      upstream_registry_url = "https://registry-1.docker.io"
      tags = {
        Purpose = "cache"
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
        },
        {
          description = "Internal app communication"
          from_port   = 8080
          to_port     = 8080
          protocol    = "tcp"
          security_groups = ["self"]
        }
      ]
    }
    
    database = {
      name = "database"
      description = "Security group for database access"
      ingress_rules = [
        {
          description = "PostgreSQL from app"
          from_port   = 5432
          to_port     = 5432
          protocol    = "tcp"
          security_groups = ["self"]
        }
      ]
    }
  }

  # Monitoring and Observability
  enable_cloudwatch_container_insights = true
  enable_aws_load_balancer_controller = true
  enable_metrics_server = true
  enable_cluster_autoscaler = true
  
  # Prometheus Monitoring
  enable_prometheus_monitoring = true
  prometheus_config = {
    grafana_admin_password = "SecurePassword123!"
    retention_days = 30
    storage_size = "100Gi"
  }
  
  # Kubernetes Dashboard
  enable_kubernetes_dashboard = true
  
  # Jaeger Tracing
  enable_jaeger_tracing = true
  jaeger_config = {
    elasticsearch_url = "https://elasticsearch.example.com:9200"
    elasticsearch_username = "jaeger"
    elasticsearch_password = "SecurePassword123!"
  }
  
  # Network Policies
  enable_network_policies = true
  network_policy_provider = "calico"
  
  # Backup and Disaster Recovery
  enable_velero_backup = true
  velero_backup_config = {
    backup_location_bucket = "enterprise-app-backups"
    backup_location_region = "us-west-2"
    schedule = "0 2 * * *"  # Daily at 2 AM
    retention_days = 90
  }

  # Common Tags
  tags = {
    Project     = "enterprise-app"
    Environment = "prod"
    Owner       = "platform-team"
    CostCenter  = "engineering"
    Compliance  = "sox"
  }
} 