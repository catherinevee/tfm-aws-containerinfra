# Enhanced AWS Container Infrastructure Module

A comprehensive Terraform module for provisioning production-ready container infrastructure on AWS, including EKS clusters, ECR repositories, security groups, and monitoring solutions with extensive customization options.

## 🚀 Features

### Core Infrastructure
- **Enhanced VPC Configuration**: Advanced VPC setup with DHCP options, NAT gateways, and flow logs
- **Multi-AZ Subnet Architecture**: Public, private, and database subnets with proper tagging
- **Security Groups**: Comprehensive security group configuration with IPv6 support
- **EKS Clusters**: Production-ready EKS clusters with enhanced security and monitoring

### Enhanced EKS Features
- **Node Groups**: On-demand and spot instances with advanced configuration options
- **Fargate Profiles**: Serverless container execution with custom IAM roles
- **Cluster Add-ons**: VPC CNI, CoreDNS, kube-proxy, and EBS CSI driver
- **Encryption**: Cluster and node group encryption with KMS
- **IRSA**: IAM Roles for Service Accounts support

### Container Registry
- **ECR Repositories**: Enhanced ECR setup with lifecycle policies and cross-account access
- **Vulnerability Scanning**: Automated container vulnerability scanning
- **Pull-Through Cache**: Docker Hub and other registry caching
- **Repository Policies**: Fine-grained access control

### Monitoring & Observability
- **CloudWatch Container Insights**: Real-time container monitoring
- **Prometheus Stack**: Complete monitoring solution with Grafana
- **Metrics Server**: Kubernetes metrics aggregation
- **Kubernetes Dashboard**: Web-based cluster management

### Security & Compliance
- **Network Policies**: Calico and Cilium support
- **IAM Roles**: Enhanced IAM configuration with permissions boundaries
- **Security Groups**: Advanced security group rules with descriptions
- **Encryption**: End-to-end encryption for data at rest and in transit

### Backup & Disaster Recovery
- **Velero**: Kubernetes backup and restore solution
- **Automated Backups**: Configurable backup schedules and retention
- **Cross-Region Support**: Multi-region backup strategies

## 📋 Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |
| kubernetes | ~> 2.0 |
| helm | ~> 2.0 |

## 🔧 Usage

### Basic Example

```hcl
module "container_infrastructure" {
  source = "path/to/module"

  name        = "my-app"
  environment = "dev"

  # Enhanced VPC Configuration
  vpc_config = {
    cidr_block = "10.0.0.0/16"
    enable_nat_gateway = true
    single_nat_gateway = true
    enable_flow_log = true
    flow_log_retention_in_days = 7
    
    # Enhanced VPC Configuration
    enable_dhcp_options = true
    dhcp_options_domain_name = "dev.internal"
    dhcp_options_domain_name_servers = ["AmazonProvidedDNS", "8.8.8.8"]
    
    # Enhanced NAT Gateway Configuration
    nat_gateway_destination_cidr_block = "0.0.0.0/0"
    nat_eip_tags = {
      Purpose = "NAT Gateway"
      Environment = "dev"
    }
  }

  # Enhanced Subnet Configuration
  subnet_config = {
    azs             = ["us-west-2a", "us-west-2b"]
    private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
    public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
    database_subnets = ["10.0.201.0/24", "10.0.202.0/24"]
  }

  # Enhanced EKS Configuration
  eks_config = {
    cluster_version = "1.28"
    enable_irsa = true
    create_cloudwatch_log_group = true
    
    # Enhanced EKS Configuration
    cluster_encryption_config = [
      {
        provider_key_arn = null
        resources = ["secrets"]
      }
    ]
    
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
      iam_role_use_name_prefix = true
      iam_role_description = "EKS node group IAM role"
      
      # Enhanced Storage Configuration
      ebs_optimized = true
      enable_spot_instance = false
      
      labels = {
        node-type = "general"
        environment = "dev"
      }
    }
    
    spot = {
      name           = "spot"
      instance_types = ["t3.medium", "t3.small"]
      capacity_type  = "SPOT"
      desired_size   = 1
      max_size       = 3
      min_size       = 0
      
      # Enhanced Storage Configuration
      ebs_optimized = true
      enable_spot_instance = true
      spot_price = "0.05"
      
      taints = [
        {
          key = "spot"
          value = "true"
          effect = "NO_SCHEDULE"
        }
      ]
    }
  }

  # Enhanced ECR Repositories
  ecr_repositories = {
    app = {
      name = "my-app"
      image_tag_mutability = "MUTABLE"
      scan_on_push = true
      encryption_type = "AES256"
      force_delete = true
      lifecycle_policy = {
        max_image_count = 30
        max_age_days    = 90
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
        }
      ]
    }
  }

  # Enhanced Monitoring
  enable_cloudwatch_container_insights = true
  enable_aws_load_balancer_controller = true
  enable_metrics_server = true
  enable_cluster_autoscaler = true

  tags = {
    Project     = "my-app"
    Environment = "dev"
    Owner       = "devops-team"
  }
}
```

### Advanced Enterprise Example

```hcl
module "enterprise_container_infrastructure" {
  source = "path/to/module"

  name        = "enterprise-app"
  environment = "prod"

  # Enterprise VPC Configuration
  vpc_config = {
    cidr_block = "10.0.0.0/16"
    enable_nat_gateway = true
    one_nat_gateway_per_az = true
    enable_flow_log = true
    flow_log_retention_in_days = 30
    
    # Enhanced VPC Configuration
    enable_dhcp_options = true
    dhcp_options_domain_name = "prod.internal"
    dhcp_options_domain_name_servers = ["AmazonProvidedDNS"]
    dhcp_options_ntp_servers = ["169.254.169.123"]
    
    # Enhanced Flow Log Configuration
    flow_log_max_aggregation_interval = 60
    flow_log_traffic_type = "ALL"
  }

  # Enhanced Security Groups Configuration
  security_groups_config = {
    revoke_rules_on_delete = true
  }

  # Enterprise EKS Configuration
  eks_config = {
    cluster_version = "1.28"
    enable_irsa = true
    create_cloudwatch_log_group = true
    cluster_log_retention_in_days = 30
    
    # Enhanced EKS Configuration
    cluster_encryption_config = [
      {
        provider_key_arn = aws_kms_key.eks.arn
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
    
    # Enterprise Add-ons Configuration
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
          replicaCount = 3
        })
      }
      aws-ebs-csi-driver = {
        most_recent = true
        service_account_role_arn = aws_iam_role.ebs_csi_driver.arn
      }
    }
  }

  # Enterprise Node Groups
  eks_node_groups = {
    general = {
      name           = "general"
      instance_types = ["m5.large", "m5.xlarge"]
      capacity_type  = "ON_DEMAND"
      desired_size   = 3
      max_size       = 10
      min_size       = 1
      disk_size      = 50
      disk_type      = "gp3"
      
      # Enhanced Node Group Configuration
      use_name_prefix = true
      iam_role_use_name_prefix = true
      iam_role_description = "EKS node group IAM role"
      iam_role_permissions_boundary = aws_iam_policy.permissions_boundary.arn
      
      # Enhanced Storage Configuration
      ebs_optimized = true
      enable_spot_instance = false
      
      # Enhanced Block Device Mappings
      block_device_mappings = [
        {
          device_name = "/dev/xvda"
          ebs = {
            delete_on_termination = true
            encrypted = true
            kms_key_id = aws_kms_key.ebs.arn
            volume_size = 50
            volume_type = "gp3"
            iops = 3000
            throughput = 125
          }
        }
      ]
      
      labels = {
        node-type = "general"
        environment = "prod"
      }
    }
    
    spot = {
      name           = "spot"
      instance_types = ["m5.large", "m5.xlarge", "m4.large"]
      capacity_type  = "SPOT"
      desired_size   = 2
      max_size       = 8
      min_size       = 0
      disk_size      = 50
      disk_type      = "gp3"
      
      # Enhanced Storage Configuration
      ebs_optimized = true
      enable_spot_instance = true
      spot_price = "0.10"
      
      taints = [
        {
          key = "spot"
          value = "true"
          effect = "NO_SCHEDULE"
        }
      ]
      
      labels = {
        node-type = "spot"
        environment = "prod"
      }
    }
  }

  # Enterprise ECR Configuration
  ecr_repositories = {
    app = {
      name = "enterprise-app"
      image_tag_mutability = "IMMUTABLE"
      scan_on_push = true
      encryption_type = "KMS"
      kms_key_id = aws_kms_key.ecr.arn
      force_delete = false
      lifecycle_policy = {
        max_image_count = 50
        max_age_days    = 180
      }
      cross_account_access = {
        account_ids = ["123456789012", "987654321098"]
        organization_id = "o-xxxxxxxxxx"
      }
    }
  }

  # Enterprise Security Groups
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
        }
      ]
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
    }
  }

  # Enterprise Monitoring
  enable_cloudwatch_container_insights = true
  enable_aws_load_balancer_controller = true
  enable_metrics_server = true
  enable_cluster_autoscaler = true
  enable_network_policies = true
  network_policy_provider = "calico"
  enable_prometheus_monitoring = true
  enable_velero_backup = true

  # Enterprise Backup Configuration
  velero_backup_config = {
    backup_location_bucket = aws_s3_bucket.backups.id
    backup_location_region = "us-west-2"
    schedule = "0 2 * * *"
    retention_days = 90
  }

  # Enterprise Prometheus Configuration
  prometheus_config = {
    grafana_admin_password = var.grafana_password
    retention_days = 30
    storage_size = "100Gi"
  }

  tags = {
    Project     = "enterprise-app"
    Environment = "prod"
    Owner       = "platform-team"
    CostCenter  = "engineering"
  }
}
```

## 📚 Inputs

### Required Variables

| Name | Description | Type | Default |
|------|-------------|------|---------|
| name | Name prefix for all resources | `string` | n/a |
| vpc_config | VPC configuration with enhanced options | `object` | n/a |
| subnet_config | Subnet configuration | `object` | n/a |

### Enhanced VPC Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| vpc_config.enable_dhcp_options | Enable DHCP options | `bool` | `false` |
| vpc_config.dhcp_options_domain_name | DHCP domain name | `string` | `null` |
| vpc_config.dhcp_options_domain_name_servers | DHCP domain name servers | `list(string)` | `["AmazonProvidedDNS"]` |
| vpc_config.nat_gateway_destination_cidr_block | NAT gateway destination CIDR | `string` | `"0.0.0.0/0"` |
| vpc_config.flow_log_max_aggregation_interval | Flow log aggregation interval | `number` | `600` |

### Enhanced EKS Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| eks_config.cluster_encryption_config | Cluster encryption configuration | `list(object)` | `[]` |
| eks_config.cluster_addons | EKS cluster add-ons | `map(object)` | `{}` |
| eks_node_groups.*.use_name_prefix | Use name prefix for node groups | `bool` | `true` |
| eks_node_groups.*.iam_role_permissions_boundary | IAM role permissions boundary | `string` | `null` |
| eks_node_groups.*.block_device_mappings | Block device mappings | `list(object)` | `[]` |

### Enhanced ECR Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| ecr_repositories.*.force_delete | Force delete ECR repository | `bool` | `false` |
| ecr_repositories.*.cross_account_access | Cross-account access configuration | `object` | `null` |
| enable_ecr_vulnerability_scanning | Enable ECR vulnerability scanning | `bool` | `true` |

### Enhanced Security Groups

| Name | Description | Type | Default |
|------|-------------|------|---------|
| security_groups_config.revoke_rules_on_delete | Revoke rules on delete | `bool` | `false` |
| security_groups.*.revoke_rules_on_delete | Revoke rules on delete for specific SG | `bool` | `null` |
| security_groups.*.ingress_rules.*.ipv6_cidr_blocks | IPv6 CIDR blocks | `list(string)` | `[]` |

## 📤 Outputs

| Name | Description |
|------|-------------|
| vpc_id | The ID of the VPC |
| cluster_id | EKS cluster ID |
| cluster_endpoint | Endpoint for EKS control plane |
| cluster_iam_role_arn | IAM role ARN associated with EKS cluster |
| eks_managed_node_groups | Map of EKS managed node groups |
| ecr_repository_urls | Map of ECR repository URLs |
| custom_security_group_ids | Map of custom security group IDs |
| kubeconfig | Kubeconfig file content |
| cloudwatch_container_insights_status | Status of CloudWatch Container Insights |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Enhanced Container Infrastructure        │
├─────────────────────────────────────────────────────────────┤
│  VPC with Enhanced Configuration                            │
│  ├── Public Subnets (ALB, NAT Gateway)                     │
│  ├── Private Subnets (EKS Nodes, ECS Tasks)                │
│  ├── Database Subnets (RDS, ElastiCache)                   │
│  └── Enhanced Security Groups                              │
├─────────────────────────────────────────────────────────────┤
│  EKS Cluster with Enhanced Features                        │
│  ├── On-Demand Node Groups                                 │
│  ├── Spot Node Groups                                      │
│  ├── Fargate Profiles                                      │
│  ├── Cluster Add-ons (VPC CNI, CoreDNS, etc.)             │
│  └── Enhanced IAM Roles                                    │
├─────────────────────────────────────────────────────────────┤
│  ECR with Enhanced Security                                │
│  ├── Repositories with Lifecycle Policies                  │
│  ├── Vulnerability Scanning                                │
│  ├── Pull-Through Cache                                    │
│  └── Cross-Account Access                                  │
├─────────────────────────────────────────────────────────────┤
│  Monitoring & Observability                                │
│  ├── CloudWatch Container Insights                         │
│  ├── Prometheus Stack                                      │
│  ├── Metrics Server                                        │
│  └── Kubernetes Dashboard                                  │
├─────────────────────────────────────────────────────────────┤
│  Security & Compliance                                     │
│  ├── Network Policies (Calico/Cilium)                     │
│  ├── Enhanced IAM Roles                                    │
│  ├── Security Groups with IPv6                             │
│  └── End-to-End Encryption                                 │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Security Features

### Encryption
- **Cluster Encryption**: EKS cluster secrets encrypted with KMS
- **Node Group Encryption**: EBS volumes encrypted with KMS
- **ECR Encryption**: Container images encrypted with KMS
- **Flow Log Encryption**: VPC flow logs encrypted with KMS

### IAM Security
- **IRSA**: IAM Roles for Service Accounts
- **Permissions Boundaries**: IAM role permissions boundaries
- **Least Privilege**: Minimal required permissions
- **Cross-Account Access**: Secure cross-account ECR access

### Network Security
- **Security Groups**: Comprehensive security group rules
- **Network Policies**: Pod-to-pod communication control
- **Private Subnets**: EKS nodes in private subnets
- **VPC Flow Logs**: Network traffic monitoring

## 📊 Monitoring & Observability

### CloudWatch Container Insights
- Real-time container metrics
- Performance monitoring
- Resource utilization tracking
- Custom dashboards

### Prometheus Stack
- Metrics collection and storage
- Grafana dashboards
- Alerting rules
- Service discovery

### Kubernetes Dashboard
- Web-based cluster management
- Resource monitoring
- Pod management
- RBAC integration

## 🚀 Getting Started

1. **Clone the module**:
   ```bash
   git clone <repository-url>
   cd tfm-aws-containerinfra
   ```

2. **Configure your variables**:
   ```bash
   cp examples/basic/main.tf .
   # Edit main.tf with your configuration
   ```

3. **Initialize Terraform**:
   ```bash
   terraform init
   ```

4. **Plan your deployment**:
   ```bash
   terraform plan
   ```

5. **Apply the configuration**:
   ```bash
   terraform apply
   ```

## 🔧 Examples

See the `examples/` directory for comprehensive examples:

- **Basic**: Simple development setup
- **Advanced**: Production-ready configuration
- **Enterprise**: Multi-region, high-availability setup

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- Create an issue in the repository
- Check the documentation
- Review the examples

## 📈 Roadmap

- [ ] Multi-region support
- [ ] GitOps integration
- [ ] Advanced monitoring
- [ ] Cost optimization features
- [ ] Compliance frameworks