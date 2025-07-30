# ==============================================================================
# General Variables
# ==============================================================================

variable "name" {
  description = "Name prefix for all resources"
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.name))
    error_message = "Name must start with a letter and contain only alphanumeric characters and hyphens."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ==============================================================================
# VPC Variables
# ==============================================================================

variable "vpc_config" {
  description = "VPC configuration"
  type = object({
    cidr_block           = string
    enable_dns_hostnames = optional(bool, true)
    enable_dns_support   = optional(bool, true)
    enable_nat_gateway   = optional(bool, true)
    single_nat_gateway   = optional(bool, false)
    one_nat_gateway_per_az = optional(bool, false)
    enable_vpn_gateway   = optional(bool, false)
    enable_flow_log      = optional(bool, false)
    flow_log_retention_in_days = optional(number, 7)
  })
  validation {
    condition     = can(cidrhost(var.vpc_config.cidr_block, 0))
    error_message = "VPC CIDR block must be a valid IPv4 CIDR."
  }
}

variable "subnet_config" {
  description = "Subnet configuration"
  type = object({
    public_subnets  = list(string)
    private_subnets = list(string)
    database_subnets = optional(list(string), [])
    azs             = list(string)
  })
  validation {
    condition = alltrue([
      for subnet in var.subnet_config.public_subnets : can(cidrhost(subnet, 0))
    ])
    error_message = "All public subnet CIDR blocks must be valid IPv4 CIDRs."
  }
  validation {
    condition = alltrue([
      for subnet in var.subnet_config.private_subnets : can(cidrhost(subnet, 0))
    ])
    error_message = "All private subnet CIDR blocks must be valid IPv4 CIDRs."
  }
}

# ==============================================================================
# EKS Variables
# ==============================================================================

variable "eks_config" {
  description = "EKS cluster configuration"
  type = object({
    cluster_version = optional(string, "1.28")
    cluster_endpoint_private_access = optional(bool, true)
    cluster_endpoint_public_access  = optional(bool, true)
    cluster_endpoint_public_access_cidrs = optional(list(string), ["0.0.0.0/0"])
    cluster_service_ipv4_cidr = optional(string, "172.16.0.0/12")
    cluster_ip_family = optional(string, "ipv4")
    enable_irsa = optional(bool, true)
    enable_cluster_creator_admin_permissions = optional(bool, true)
    create_cloudwatch_log_group = optional(bool, true)
    cluster_log_retention_in_days = optional(number, 7)
    cluster_log_types = optional(list(string), ["api", "audit", "authenticator", "controllerManager", "scheduler"])
  })
  default = {}
}

variable "eks_node_groups" {
  description = "EKS node groups configuration"
  type = map(object({
    name = string
    instance_types = list(string)
    capacity_type = optional(string, "ON_DEMAND")
    disk_size = optional(number, 20)
    disk_type = optional(string, "gp3")
    ami_type = optional(string, "AL2_x86_64")
    platform = optional(string, "linux")
    desired_size = optional(number, 2)
    max_size = optional(number, 5)
    min_size = optional(number, 1)
    max_unavailable = optional(number, 1)
    max_unavailable_percentage = optional(number, null)
    force_update_version = optional(bool, false)
    update_config = optional(object({
      max_unavailable_percentage = optional(number, 33)
    }), {})
    labels = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "eks_fargate_profiles" {
  description = "EKS Fargate profiles configuration"
  type = map(object({
    name = string
    selectors = list(object({
      namespace = string
      labels = optional(map(string), {})
    }))
    subnets = optional(list(string), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# ECR Variables
# ==============================================================================

variable "ecr_repositories" {
  description = "ECR repositories configuration"
  type = map(object({
    name = string
    image_tag_mutability = optional(string, "MUTABLE")
    scan_on_push = optional(bool, true)
    encryption_type = optional(string, "AES256")
    kms_key_id = optional(string, null)
    lifecycle_policy = optional(object({
      max_image_count = optional(number, 30)
      max_age_days = optional(number, 90)
    }), {})
    cross_account_access = optional(object({
      account_ids = list(string)
      organization_id = string
    }), null)
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "enable_ecr_vulnerability_scanning" {
  description = "Enable ECR vulnerability scanning"
  type        = bool
  default     = true
}

variable "ecr_pull_through_cache_rules" {
  description = "ECR pull-through cache rules configuration"
  type = map(object({
    repository_prefix = string
    upstream_registry_url = string
    tags = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# Security Groups Variables
# ==============================================================================

variable "security_groups" {
  description = "Security groups configuration"
  type = map(object({
    name = string
    description = string
    vpc_id = optional(string, null)
    ingress_rules = optional(list(object({
      description = optional(string, "")
      from_port = number
      to_port = number
      protocol = string
      cidr_blocks = optional(list(string), [])
      security_groups = optional(list(string), [])
      self = optional(bool, false)
    })), [])
    egress_rules = optional(list(object({
      description = optional(string, "")
      from_port = number
      to_port = number
      protocol = string
      cidr_blocks = optional(list(string), ["0.0.0.0/0"])
      security_groups = optional(list(string), [])
      self = optional(bool, false)
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# Monitoring and Logging Variables
# ==============================================================================

variable "enable_cloudwatch_container_insights" {
  description = "Enable CloudWatch Container Insights for EKS"
  type        = bool
  default     = true
}

variable "enable_aws_load_balancer_controller" {
  description = "Enable AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "enable_metrics_server" {
  description = "Enable Metrics Server"
  type        = bool
  default     = true
}

variable "enable_cluster_autoscaler" {
  description = "Enable Cluster Autoscaler"
  type        = bool
  default     = false
}

# ==============================================================================
# Backup and Disaster Recovery Variables
# ==============================================================================

variable "enable_velero_backup" {
  description = "Enable Velero backup solution"
  type        = bool
  default     = false
}

variable "velero_backup_config" {
  description = "Velero backup configuration"
  type = object({
    backup_location_bucket = optional(string, "")
    backup_location_region = optional(string, "")
    schedule = optional(string, "0 2 * * *") # Daily at 2 AM
    retention_days = optional(number, 30)
  })
  default = {}
}

# ==============================================================================
# Network Policies Variables
# ==============================================================================

variable "enable_network_policies" {
  description = "Enable network policies"
  type        = bool
  default     = false
}

variable "network_policy_provider" {
  description = "Network policy provider (calico or cilium)"
  type        = string
  default     = "calico"
  validation {
    condition     = contains(["calico", "cilium"], var.network_policy_provider)
    error_message = "Network policy provider must be either 'calico' or 'cilium'."
  }
}

# ==============================================================================
# Monitoring and Observability Variables
# ==============================================================================

variable "enable_prometheus_monitoring" {
  description = "Enable Prometheus monitoring stack"
  type        = bool
  default     = false
}

variable "prometheus_config" {
  description = "Prometheus configuration"
  type = object({
    grafana_admin_password = string
    retention_days = optional(number, 15)
    storage_size = optional(string, "50Gi")
  })
  default = {
    grafana_admin_password = "admin123"
  }
}

variable "enable_kubernetes_dashboard" {
  description = "Enable Kubernetes Dashboard"
  type        = bool
  default     = false
}

variable "enable_jaeger_tracing" {
  description = "Enable Jaeger distributed tracing"
  type        = bool
  default     = false
}

variable "jaeger_config" {
  description = "Jaeger configuration"
  type = object({
    elasticsearch_url = string
    elasticsearch_username = string
    elasticsearch_password = string
  })
  default = {
    elasticsearch_url = "http://elasticsearch:9200"
    elasticsearch_username = "elastic"
    elasticsearch_password = "changeme"
  }
} 