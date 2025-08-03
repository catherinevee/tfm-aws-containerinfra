# ==============================================================================
# Enhanced Basic Container Infrastructure Example
# Demonstrates the enhanced features of the tfm-aws-containerinfra module
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
# Enhanced Container Infrastructure Module
# ==============================================================================

module "enhanced_container_infrastructure" {
  source = "../../"

  name        = "enhanced-app"
  environment = "dev"

  # Enhanced VPC Configuration
  vpc_config = {
    cidr_block = "10.0.0.0/16"
    enable_nat_gateway = true
    single_nat_gateway = true  # Cost optimization for dev environment
    enable_dns_hostnames = true
    enable_dns_support   = true
    enable_flow_log = true
    flow_log_retention_in_days = 7
    
    # Enhanced VPC Configuration
    enable_dhcp_options = true
    dhcp_options_domain_name = "dev.internal"
    dhcp_options_domain_name_servers = ["AmazonProvidedDNS", "8.8.8.8"]
    dhcp_options_ntp_servers = ["169.254.169.123"]
    
    # Enhanced NAT Gateway Configuration
    nat_gateway_destination_cidr_block = "0.0.0.0/0"
    nat_eip_tags = {
      Purpose = "NAT Gateway"
      Environment = "dev"
    }
    nat_gateway_tags = {
      Purpose = "NAT Gateway"
      Environment = "dev"
    }
    
    # Enhanced Flow Log Configuration
    flow_log_max_aggregation_interval = 600
    flow_log_traffic_type = "ALL"
    
    # Enhanced Subnet Tags
    public_subnet_tags = {
      "kubernetes.io/role/elb" = "1"
      "Environment" = "dev"
    }
    private_subnet_tags = {
      "kubernetes.io/role/internal-elb" = "1"
      "Environment" = "dev"
    }
    database_subnet_tags = {
      "Environment" = "dev"
    }
  }

  # Enhanced Subnet Configuration
  subnet_config = {
    azs             = ["us-west-2a", "us-west-2b"]
    private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
    public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
    database_subnets = ["10.0.201.0/24", "10.0.202.0/24"]
  }

  # Enhanced Security Groups Configuration
  security_groups_config = {
    revoke_rules_on_delete = true
  }

  # Enhanced EKS Configuration
  eks_config = {
    cluster_version = "1.28"
    cluster_endpoint_private_access = true
    cluster_endpoint_public_access = true
    cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
    cluster_service_ipv4_cidr = "172.16.0.0/12"
    cluster_ip_family = "ipv4"
    enable_irsa = true
    enable_cluster_creator_admin_permissions = true
    create_cloudwatch_log_group = true
    cluster_log_retention_in_days = 7
    cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    
    # Enhanced EKS Configuration
    cluster_encryption_config = [
      {
        provider_key_arn = null  # Use AWS managed key
        resources = ["secrets"]
      }
    ]
    
    # Enhanced Security Group Configuration
    cluster_security_group_additional_rules = {
      ingress_nodes_443 = {
        description = "Node groups to cluster API"
        protocol = "tcp"
        from_port = 443
        to_port = 443
        type = "ingress"
        source_node_security_group = true
      }
    }
    
    node_security_group_additional_rules = {
      ingress_self_all = {
        description = "Node to node all ports/protocols"
        protocol = "-1"
        from_port = 0
        to_port = 0
        type = "ingress"
        self = true
      }
      egress_all = {
        description = "Node all egress"
        protocol = "-1"
        from_port = 0
        to_port = 0
        type = "egress"
        cidr_blocks = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
      }
    }
    
    # Enhanced Add-ons Configuration
    cluster_addons = {
      vpc-cni = {
        most_recent = true
        before_compute = true
        configuration_values = jsonencode({
          env = {
            ENABLE_PREFIX_DELEGATION = "true"
            WARM_PREFIX_TARGET = "1"
          }
        })
      }
      coredns = {
        most_recent = true
        configuration_values = jsonencode({
          replicaCount = 2
        })
      }
      kube-proxy = {
        most_recent = true
      }
      aws-ebs-csi-driver = {
        most_recent = true
        service_account_role_arn = null
      }
    }
  }

  # Enhanced EKS Node Groups
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
      
      # Enhanced Node Group Configuration
      use_name_prefix = true
      use_custom_launch_template = false
      create_launch_template = false
      
      # Enhanced IAM Configuration
      iam_role_use_name_prefix = true
      iam_role_description = "EKS node group IAM role"
      iam_role_path = "/"
      
      # Enhanced Security Configuration
      vpc_security_group_ids = []
      
      # Enhanced Monitoring Configuration
      enable_monitoring = true
      enable_bootstrap_user_data = true
      
      # Enhanced Storage Configuration
      ebs_optimized = true
      enable_spot_instance = false
      
      # Enhanced Scaling Configuration
      scaling_config = {
        desired_size = 2
        max_size = 4
        min_size = 1
      }
      
      labels = {
        node-type = "general"
        environment = "dev"
      }
      
      taints = []
      
      tags = {
        NodeGroupType = "general"
        Environment = "dev"
      }
    }
    
    spot = {
      name           = "spot"
      instance_types = ["t3.medium", "t3.small"]
      capacity_type  = "SPOT"
      desired_size   = 1
      max_size       = 3
      min_size       = 0
      disk_size      = 20
      disk_type      = "gp3"
      
      # Enhanced Node Group Configuration
      use_name_prefix = true
      use_custom_launch_template = false
      create_launch_template = false
      
      # Enhanced IAM Configuration
      iam_role_use_name_prefix = true
      iam_role_description = "EKS spot node group IAM role"
      iam_role_path = "/"
      
      # Enhanced Security Configuration
      vpc_security_group_ids = []
      
      # Enhanced Monitoring Configuration
      enable_monitoring = true
      enable_bootstrap_user_data = true
      
      # Enhanced Storage Configuration
      ebs_optimized = true
      enable_spot_instance = true
      spot_price = "0.05"
      
      # Enhanced Scaling Configuration
      scaling_config = {
        desired_size = 1
        max_size = 3
        min_size = 0
      }
      
      labels = {
        node-type = "spot"
        environment = "dev"
      }
      
      taints = [
        {
          key = "spot"
          value = "true"
          effect = "NO_SCHEDULE"
        }
      ]
      
      tags = {
        NodeGroupType = "spot"
        Environment = "dev"
      }
    }
  }

  # Enhanced EKS Fargate Profiles
  eks_fargate_profiles = {
    default = {
      name = "default"
      selectors = [
        {
          namespace = "default"
          labels = {}
        },
        {
          namespace = "kube-system"
          labels = {}
        }
      ]
      subnets = []
      
      # Enhanced Fargate Configuration
      iam_role_use_name_prefix = true
      iam_role_description = "EKS Fargate profile IAM role"
      iam_role_path = "/"
      
      tags = {
        FargateProfileType = "default"
        Environment = "dev"
      }
    }
  }

  # Enhanced ECR Repositories
  ecr_repositories = {
    app = {
      name = "enhanced-app"
      image_tag_mutability = "MUTABLE"
      scan_on_push = true
      encryption_type = "AES256"
      force_delete = true
      lifecycle_policy = {
        max_image_count = 30
        max_age_days    = 90
      }
      tags = {
        RepositoryType = "application"
        Environment = "dev"
      }
    }
    
    nginx = {
      name = "nginx"
      image_tag_mutability = "IMMUTABLE"
      scan_on_push = true
      encryption_type = "AES256"
      force_delete = true
      lifecycle_policy = {
        max_image_count = 20
        max_age_days    = 60
      }
      tags = {
        RepositoryType = "nginx"
        Environment = "dev"
      }
    }
  }

  # Enhanced ECR Vulnerability Scanning
  enable_ecr_vulnerability_scanning = true
  ecr_vulnerability_scanning_config = {
    scan_type = "ENHANCED"
    rules = [
      {
        scan_frequency = "CONTINUOUS_SCAN"
        repository_filter = {
          filter = "*"
          filter_type = "WILDCARD"
        }
      }
    ]
  }

  # Enhanced ECR Pull Through Cache Rules
  ecr_pull_through_cache_rules = {
    docker_hub = {
      repository_prefix = "docker.io"
      upstream_registry_url = "https://registry-1.docker.io"
      tags = {
        CacheType = "docker-hub"
        Environment = "dev"
      }
    }
  }

  # Enhanced Security Groups
  security_groups = {
    app = {
      name = "app"
      description = "Security group for application pods"
      revoke_rules_on_delete = true
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
          description = "Application port"
          from_port   = 8080
          to_port     = 8080
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/16"]
        }
      ]
      egress_rules = [
        {
          description = "Allow all outbound traffic"
          from_port   = 0
          to_port     = 0
          protocol    = "-1"
          cidr_blocks = ["0.0.0.0/0"]
        }
      ]
      tags = {
        SecurityGroupType = "application"
        Environment = "dev"
      }
    }
    
    database = {
      name = "database"
      description = "Security group for database access"
      revoke_rules_on_delete = true
      ingress_rules = [
        {
          description = "PostgreSQL from app"
          from_port   = 5432
          to_port     = 5432
          protocol    = "tcp"
          security_groups = ["app"]
        }
      ]
      egress_rules = [
        {
          description = "Allow all outbound traffic"
          from_port   = 0
          to_port     = 0
          protocol    = "-1"
          cidr_blocks = ["0.0.0.0/0"]
        }
      ]
      tags = {
        SecurityGroupType = "database"
        Environment = "dev"
      }
    }
  }

  # Enhanced Monitoring and Logging
  enable_cloudwatch_container_insights = true
  cloudwatch_container_insights_config = {
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {
      "clusterName" = "enhanced-app-eks-cluster"
      "region" = "us-west-2"
    }
  }

  enable_aws_load_balancer_controller = true
  aws_load_balancer_controller_config = {
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {
      "clusterName" = "enhanced-app-eks-cluster"
      "region" = "us-west-2"
    }
  }

  enable_metrics_server = true
  metrics_server_config = {
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {
      "args[0]" = "--kubelet-insecure-tls"
    }
  }

  enable_cluster_autoscaler = true
  cluster_autoscaler_config = {
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {
      "autoDiscovery.clusterName" = "enhanced-app-eks-cluster"
      "awsRegion" = "us-west-2"
    }
  }

  # Enhanced Backup and Disaster Recovery
  enable_velero_backup = false  # Set to true if you have an S3 bucket for backups
  velero_backup_config = {
    backup_location_bucket = ""
    backup_location_region = "us-west-2"
    schedule = "0 2 * * *"  # Daily at 2 AM
    retention_days = 30
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {}
  }

  # Enhanced Network Policies
  enable_network_policies = false  # Set to true if you want to enable network policies
  network_policy_provider = "calico"
  network_policy_config = {
    calico = {
      version = null
      timeout = 300
      wait = true
      atomic = false
      cleanup_on_fail = false
      additional_settings = {}
    }
    cilium = {
      version = null
      timeout = 300
      wait = true
      atomic = false
      cleanup_on_fail = false
      additional_settings = {}
    }
  }

  # Enhanced Monitoring and Observability
  enable_prometheus_monitoring = false  # Set to true if you want Prometheus monitoring
  prometheus_config = {
    grafana_admin_password = "admin123"
    retention_days = 15
    storage_size = "50Gi"
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {}
  }

  enable_kubernetes_dashboard = false  # Set to true if you want Kubernetes Dashboard
  kubernetes_dashboard_config = {
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {}
  }

  enable_jaeger_tracing = false  # Set to true if you want Jaeger tracing
  jaeger_config = {
    elasticsearch_url = "http://elasticsearch:9200"
    elasticsearch_username = "elastic"
    elasticsearch_password = "changeme"
    version = null
    timeout = 300
    wait = true
    atomic = false
    cleanup_on_fail = false
    additional_settings = {}
  }

  # Common tags
  tags = {
    Project     = "enhanced-app"
    Environment = "dev"
    Owner       = "devops-team"
    CostCenter  = "engineering"
    ManagedBy   = "terraform"
    Purpose     = "container-infrastructure"
  }
} 