# AWS Container Infrastructure Terraform Module

A comprehensive Terraform module for deploying production-ready container infrastructure on AWS, including EKS (Elastic Kubernetes Service), ECR (Elastic Container Registry), VPC networking, security groups, and advanced monitoring/observability features.

## 🚀 Features

### Core Infrastructure
- **EKS Cluster**: Fully managed Kubernetes cluster with configurable node groups and Fargate profiles
- **ECR Repositories**: Container image repositories with lifecycle policies, vulnerability scanning, and cross-account access
- **VPC Networking**: Complete VPC setup with public/private subnets, NAT gateways, and internet gateway
- **Security Groups**: Configurable security groups for EKS cluster, nodes, and custom applications

### Advanced ECR Features
- **Vulnerability Scanning**: Enhanced scanning with continuous monitoring
- **Cross-Account Access**: Secure sharing across AWS accounts within your organization
- **Pull-Through Cache**: Cache external registries like Docker Hub for faster builds
- **Lifecycle Policies**: Automatic cleanup of old images to manage costs
- **KMS Encryption**: Server-side encryption for enhanced security

### Monitoring & Observability
- **CloudWatch Container Insights**: Native AWS monitoring and logging
- **Prometheus Stack**: Complete monitoring solution with Grafana dashboards
- **Kubernetes Dashboard**: Web-based UI for cluster management
- **Jaeger Tracing**: Distributed tracing for microservices
- **Metrics Server**: Kubernetes metrics aggregation

### Load Balancing & Auto Scaling
- **AWS Load Balancer Controller**: Kubernetes-native load balancing
- **Cluster Autoscaler**: Automatic node scaling based on demand
- **Spot Instances**: Cost optimization with spot instance support

### Security & Compliance
- **IRSA (IAM Roles for Service Accounts)**: Fine-grained IAM permissions
- **Network Policies**: Calico and Cilium support for pod-to-pod communication control
- **Pod Security Standards**: Kubernetes security best practices
- **Encryption**: End-to-end encryption for data at rest and in transit

### Backup & Disaster Recovery
- **Velero**: Kubernetes backup and disaster recovery solution
- **Automated Backups**: Configurable backup schedules and retention policies

## 📋 Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate permissions
- kubectl (for cluster interaction)
- helm (for add-on management)

## 🏗️ Usage

### Basic Example

```hcl
module "container_infrastructure" {
  source = "./tfm-aws-containerinfra"

  name        = "my-app"
  environment = "prod"

  vpc_config = {
    cidr_block = "10.0.0.0/16"
    enable_nat_gateway = true
    single_nat_gateway = false
  }

  subnet_config = {
    azs             = ["us-west-2a", "us-west-2b", "us-west-2c"]
    private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  }

  eks_node_groups = {
    general = {
      name           = "general"
      instance_types = ["t3.medium"]
      desired_size   = 2
      max_size       = 5
      min_size       = 1
    }
  }

  ecr_repositories = {
    app = {
      name = "my-app"
      lifecycle_policy = {
        max_image_count = 30
        max_age_days    = 90
      }
    }
  }

  tags = {
    Project     = "my-app"
    Environment = "prod"
    Owner       = "devops-team"
  }
}
```

### Advanced Example with All Features

```hcl
module "container_infrastructure" {
  source = "./tfm-aws-containerinfra"

  name        = "enterprise-app"
  environment = "prod"

  # VPC Configuration
  vpc_config = {
    cidr_block = "10.0.0.0/16"
    enable_nat_gateway = true
    single_nat_gateway = false
    enable_flow_log = true
    flow_log_retention_in_days = 30
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
    enable_irsa = true
    create_cloudwatch_log_group = true
    cluster_log_retention_in_days = 30
  }

  # EKS Node Groups with Spot Instances
  eks_node_groups = {
    general = {
      name           = "general"
      instance_types = ["t3.medium", "t3.large"]
      capacity_type  = "ON_DEMAND"
      desired_size   = 3
      max_size       = 10
      min_size       = 1
    }
    
    spot = {
      name           = "spot"
      instance_types = ["t3.medium", "t3.large", "m5.large"]
      capacity_type  = "SPOT"
      desired_size   = 2
      max_size       = 8
      min_size       = 0
      taints = [
        {
          key    = "spot"
          value  = "true"
          effect = "NO_SCHEDULE"
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
    }
  }

  # ECR Pull Through Cache
  ecr_pull_through_cache_rules = {
    docker_hub = {
      repository_prefix = "docker.io"
      upstream_registry_url = "https://registry-1.docker.io"
    }
  }

  # Monitoring and Observability
  enable_prometheus_monitoring = true
  prometheus_config = {
    grafana_admin_password = "SecurePassword123!"
    retention_days = 30
  }
  
  enable_kubernetes_dashboard = true
  enable_jaeger_tracing = true
  
  # Security Features
  enable_network_policies = true
  network_policy_provider = "calico"
  
  # Backup and Disaster Recovery
  enable_velero_backup = true
  velero_backup_config = {
    backup_location_bucket = "enterprise-app-backups"
    backup_location_region = "us-west-2"
    schedule = "0 2 * * *"
    retention_days = 90
  }

  tags = {
    Project     = "enterprise-app"
    Environment = "prod"
    Owner       = "platform-team"
  }
}
```

## 📚 Documentation

### Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name | Name prefix for all resources | `string` | n/a | yes |
| environment | Environment name (dev, staging, prod) | `string` | `"dev"` | no |
| vpc_config | VPC configuration | `object` | n/a | yes |
| subnet_config | Subnet configuration | `object` | n/a | yes |
| eks_config | EKS cluster configuration | `object` | `{}` | no |
| eks_node_groups | EKS node groups configuration | `map(object)` | `{}` | no |
| eks_fargate_profiles | EKS Fargate profiles | `map(object)` | `{}` | no |
| ecr_repositories | ECR repositories configuration | `map(object)` | `{}` | no |
| enable_ecr_vulnerability_scanning | Enable ECR vulnerability scanning | `bool` | `true` | no |
| ecr_pull_through_cache_rules | ECR pull-through cache rules | `map(object)` | `{}` | no |
| security_groups | Security groups configuration | `map(object)` | `{}` | no |
| enable_prometheus_monitoring | Enable Prometheus monitoring stack | `bool` | `false` | no |
| enable_kubernetes_dashboard | Enable Kubernetes Dashboard | `bool` | `false` | no |
| enable_jaeger_tracing | Enable Jaeger distributed tracing | `bool` | `false` | no |
| enable_network_policies | Enable network policies | `bool` | `false` | no |
| enable_velero_backup | Enable Velero backup solution | `bool` | `false` | no |

### Outputs

| Name | Description |
|------|-------------|
| vpc_id | The ID of the VPC |
| private_subnets | List of IDs of private subnets |
| public_subnets | List of IDs of public subnets |
| cluster_id | EKS cluster ID |
| cluster_endpoint | EKS cluster endpoint |
| cluster_oidc_issuer_url | EKS cluster OIDC issuer URL |
| ecr_repository_urls | ECR repository URLs |
| ecr_vulnerability_scanning_status | Status of ECR vulnerability scanning |
| prometheus_status | Status of Prometheus monitoring stack |
| kubernetes_dashboard_status | Status of Kubernetes Dashboard |
| jaeger_status | Status of Jaeger distributed tracing |
| velero_status | Status of Velero backup solution |

## 🔧 Configuration Examples

### Cost Optimization

```hcl
# Use spot instances for cost optimization
eks_node_groups = {
  spot = {
    name           = "spot"
    instance_types = ["t3.medium", "t3.large", "m5.large"]
    capacity_type  = "SPOT"
    desired_size   = 2
    max_size       = 8
    min_size       = 0
  }
}

# Enable ECR lifecycle policies
ecr_repositories = {
  app = {
    name = "my-app"
    lifecycle_policy = {
      max_image_count = 20
      max_age_days    = 60
    }
  }
}
```

### Security Hardening

```hcl
# Enable network policies
enable_network_policies = true
network_policy_provider = "calico"

# Use KMS encryption for ECR
ecr_repositories = {
  app = {
    name = "my-app"
    encryption_type = "KMS"
    scan_on_push = true
  }
}

# Restrict EKS API access
eks_config = {
  cluster_endpoint_public_access_cidrs = ["10.0.0.0/16", "192.168.0.0/16"]
}
```

### Monitoring Setup

```hcl
# Enable comprehensive monitoring
enable_prometheus_monitoring = true
prometheus_config = {
  grafana_admin_password = "SecurePassword123!"
  retention_days = 30
}

enable_kubernetes_dashboard = true
enable_jaeger_tracing = true

# Configure Jaeger with external Elasticsearch
jaeger_config = {
  elasticsearch_url = "https://elasticsearch.example.com:9200"
  elasticsearch_username = "jaeger"
  elasticsearch_password = "SecurePassword123!"
}
```

## 🚀 Getting Started

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd tfm-aws-containerinfra
   ```

2. **Initialize Terraform**:
   ```bash
   terraform init
   ```

3. **Review the plan**:
   ```bash
   terraform plan
   ```

4. **Apply the configuration**:
   ```bash
   terraform apply
   ```

5. **Configure kubectl**:
   ```bash
   aws eks update-kubeconfig --region us-west-2 --name <cluster-name>
   ```

## 🧪 Testing

Run the test suite:

```bash
make test
```

Run examples:

```bash
make examples
```

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

For support and questions:
- Create an issue in the GitHub repository
- Check the [examples](examples/) directory for usage patterns
- Review the [variables.tf](variables.tf) file for all available options

## 🔗 Related Projects

- [AWS EKS Best Practices](https://aws.github.io/aws-eks-best-practices/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)