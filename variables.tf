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

# ==============================================================================
# Enhanced ECS Configuration Variables
# ==============================================================================

variable "ecs_clusters" {
  description = "Map of ECS clusters to create"
  type = map(object({
    name = string
    capacity_providers = optional(list(string), [])
    default_capacity_provider_strategy = optional(list(object({
      capacity_provider = string
      weight = optional(number, null)
      base = optional(number, null)
    })), [])
    setting = optional(list(object({
      name = string
      value = string
    })), [])
    configuration = optional(object({
      execute_command_configuration = optional(object({
        logging = optional(string, "DEFAULT")
        log_configuration = optional(object({
          cloud_watch_encryption_enabled = optional(bool, null)
          cloud_watch_log_group_name = optional(string, null)
          s3_bucket_name = optional(string, null)
          s3_bucket_encryption_enabled = optional(bool, null)
          s3_key_prefix = optional(string, null)
        }), {})
        kms_key_id = optional(string, null)
      }), {})
    }), {})
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecs_services" {
  description = "Map of ECS services to create"
  type = map(object({
    name = string
    cluster = string
    task_definition = string
    desired_count = optional(number, 1)
    launch_type = optional(string, null)
    platform_version = optional(string, null)
    scheduling_strategy = optional(string, "REPLICA")
    force_new_deployment = optional(bool, null)
    wait_for_steady_state = optional(bool, null)
    enable_execute_command = optional(bool, null)
    enable_ecs_managed_tags = optional(bool, null)
    propagate_tags = optional(string, null)
    health_check_grace_period_seconds = optional(number, null)
    capacity_provider_strategy = optional(list(object({
      capacity_provider = string
      weight = optional(number, null)
      base = optional(number, null)
    })), [])
    network_configuration = optional(object({
      subnets = list(string)
      security_groups = optional(list(string), [])
      assign_public_ip = optional(bool, null)
    }), {})
    load_balancer = optional(list(object({
      elb_name = optional(string, null)
      target_group_arn = optional(string, null)
      container_name = string
      container_port = number
    })), [])
    service_registries = optional(list(object({
      registry_arn = string
      port = optional(number, null)
      container_port = optional(number, null)
      container_name = optional(string, null)
    })), [])
    deployment_circuit_breaker = optional(object({
      enable = bool
      rollback = bool
    }), {})
    deployment_controller = optional(object({
      type = string
    }), {})
    deployment_maximum_percent = optional(number, null)
    deployment_minimum_healthy_percent = optional(number, null)
    desired_count = optional(number, null)
    enable_ecs_managed_tags = optional(bool, null)
    health_check_grace_period_seconds = optional(number, null)
    iam_role = optional(string, null)
    load_balancer = optional(list(object({
      elb_name = optional(string, null)
      target_group_arn = optional(string, null)
      container_name = string
      container_port = number
    })), [])
    network_configuration = optional(object({
      subnets = list(string)
      security_groups = optional(list(string), [])
      assign_public_ip = optional(bool, null)
    }), {})
    ordered_placement_strategy = optional(list(object({
      type = string
      field = optional(string, null)
    })), [])
    placement_constraints = optional(list(object({
      type = string
      expression = optional(string, null)
    })), [])
    platform_version = optional(string, null)
    propagate_tags = optional(string, null)
    service_registries = optional(list(object({
      registry_arn = string
      port = optional(number, null)
      container_port = optional(number, null)
      container_name = optional(string, null)
    })), [])
    tags = optional(map(string), {})
    task_definition = string
    wait_for_steady_state = optional(bool, null)
  }))
  default = {}
}

variable "ecs_task_definitions" {
  description = "Map of ECS task definitions to create"
  type = map(object({
    family = string
    requires_compatibilities = optional(list(string), [])
    network_mode = optional(string, "bridge")
    cpu = optional(number, null)
    memory = optional(number, null)
    execution_role_arn = optional(string, null)
    task_role_arn = optional(string, null)
    container_definitions = string
    volume = optional(list(object({
      name = string
      host_path = optional(string, null)
      docker_volume_configuration = optional(object({
        scope = optional(string, null)
        autoprovision = optional(bool, null)
        driver = optional(string, null)
        driver_opts = optional(map(string), {})
        labels = optional(map(string), {})
      }), {})
      efs_volume_configuration = optional(object({
        file_system_id = string
        root_directory = optional(string, null)
        transit_encryption = optional(string, null)
        transit_encryption_port = optional(number, null)
        authorization_config = optional(object({
          access_point_id = optional(string, null)
          iam = optional(string, null)
        }), {})
      }), {})
      fsx_windows_file_server_volume_configuration = optional(object({
        file_system_id = string
        root_directory = string
        authorization_config = object({
          credentials_parameter = string
          domain = string
        })
      }), {})
    })), [])
    placement_constraints = optional(list(object({
      type = string
      expression = optional(string, null)
    })), [])
    proxy_configuration = optional(object({
      type = string
      container_name = string
      properties = optional(map(string), {})
    }), {})
    inference_accelerator = optional(list(object({
      device_name = string
      device_type = string
    })), [])
    ephemeral_storage = optional(object({
      size_in_gib = number
    }), {})
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecs_capacity_providers" {
  description = "Map of ECS capacity providers to create"
  type = map(object({
    name = string
    auto_scaling_group_provider = object({
      auto_scaling_group_arn = string
      managed_scaling = optional(object({
        maximum_scaling_step_size = optional(number, null)
        minimum_scaling_step_size = optional(number, null)
        status = optional(string, null)
        target_capacity = optional(number, null)
      }), {})
      managed_termination_protection = optional(string, null)
    })
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecs_cluster_capacity_providers" {
  description = "Map of ECS cluster capacity providers to create"
  type = map(object({
    cluster_name = string
    capacity_providers = list(string)
    default_capacity_provider_strategy = optional(list(object({
      capacity_provider = string
      weight = optional(number, null)
      base = optional(number, null)
    })), [])
  }))
  default = {}
}

# ==============================================================================
# Enhanced EKS Configuration Variables
# ==============================================================================

variable "eks_clusters" {
  description = "Map of EKS clusters to create"
  type = map(object({
    name = string
    role_arn = string
    version = optional(string, "1.28")
    enabled_cluster_log_types = optional(list(string), [])
    encryption_config = optional(object({
      provider = object({
        key_arn = string
      })
      resources = list(string)
    }), {})
    kubernetes_network_config = optional(object({
      service_ipv4_cidr = optional(string, null)
      ip_family = optional(string, null)
    }), {})
    outpost_config = optional(object({
      control_plane_instance_type = string
      outpost_arns = list(string)
    }), {})
    vpc_config = object({
      subnet_ids = list(string)
      endpoint_private_access = optional(bool, null)
      endpoint_public_access = optional(bool, null)
      public_access_cidrs = optional(list(string), [])
      security_group_ids = optional(list(string), [])
    })
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "eks_node_groups" {
  description = "Map of EKS node groups to create"
  type = map(object({
    cluster_name = string
    node_group_name = string
    node_role_arn = string
    subnet_ids = list(string)
    ami_type = optional(string, null)
    capacity_type = optional(string, null)
    disk_size = optional(number, null)
    force_update_version = optional(bool, null)
    instance_types = optional(list(string), [])
    labels = optional(map(string), {})
    release_version = optional(string, null)
    remote_access = optional(object({
      ec2_ssh_key = optional(string, null)
      source_security_group_ids = optional(list(string), [])
    }), {})
    scaling_config = object({
      desired_size = number
      max_size = number
      min_size = number
    })
    taint = optional(list(object({
      key = string
      value = string
      effect = string
    })), [])
    update_config = optional(object({
      max_unavailable = optional(number, null)
      max_unavailable_percentage = optional(number, null)
    }), {})
    version = optional(string, null)
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "eks_fargate_profiles" {
  description = "Map of EKS Fargate profiles to create"
  type = map(object({
    cluster_name = string
    fargate_profile_name = string
    pod_execution_role_arn = string
    subnet_ids = list(string)
    selectors = list(object({
      namespace = string
      labels = optional(map(string), {})
    }))
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "eks_addons" {
  description = "Map of EKS addons to create"
  type = map(object({
    cluster_name = string
    addon_name = string
    addon_version = optional(string, null)
    resolve_conflicts = optional(string, null)
    resolve_conflicts_on_create = optional(string, null)
    resolve_conflicts_on_update = optional(string, null)
    service_account_role_arn = optional(string, null)
    configuration_values = optional(string, null)
    preserve = optional(bool, null)
    tags = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# Enhanced ECR Configuration Variables
# ==============================================================================

variable "ecr_repositories" {
  description = "Map of ECR repositories to create"
  type = map(object({
    name = string
    image_tag_mutability = optional(string, "MUTABLE")
    image_scanning_configuration = optional(object({
      scan_on_push = bool
    }), {})
    encryption_configuration = optional(object({
      encryption_type = optional(string, "AES256")
      kms_key = optional(string, null)
    }), {})
    lifecycle_policy = optional(string, null)
    force_delete = optional(bool, null)
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecr_lifecycle_policies" {
  description = "Map of ECR lifecycle policies to create"
  type = map(object({
    repository = string
    policy = string
  }))
  default = {}
}

variable "ecr_registry_policy" {
  description = "Map of ECR registry policies to create"
  type = map(object({
    policy = string
  }))
  default = {}
}

variable "ecr_registry_scanning_configuration" {
  description = "Map of ECR registry scanning configurations to create"
  type = map(object({
    scan_type = string
    rules = optional(list(object({
      repository_filters = list(object({
        filter = string
        filter_type = string
      }))
      scan_frequency = string
    })), [])
  }))
  default = {}
}

variable "ecr_pull_through_cache_rules" {
  description = "Map of ECR pull through cache rules to create"
  type = map(object({
    ecr_repository_prefix = string
    upstream_registry_url = string
    registry_id = optional(string, null)
  }))
  default = {}
}

variable "ecr_repository_policies" {
  description = "Map of ECR repository policies to create"
  type = map(object({
    repository = string
    policy = string
  }))
  default = {}
}

# ==============================================================================
# Enhanced App Runner Configuration Variables
# ==============================================================================

variable "apprunner_services" {
  description = "Map of App Runner services to create"
  type = map(object({
    service_name = string
    source_configuration = object({
      authentication_configuration = optional(object({
        access_role_arn = optional(string, null)
        connection_arn = optional(string, null)
      }), {})
      auto_deployments_enabled = optional(bool, null)
      code_repository = optional(object({
        code_configuration = optional(object({
          configuration_source = optional(string, null)
          configuration_values = optional(object({
            build_command = optional(string, null)
            port = optional(string, null)
            runtime = optional(string, null)
            runtime_environment_secrets = optional(map(string), {})
            runtime_environment_variables = optional(map(string), {})
            start_command = optional(string, null)
          }), {})
        }), {})
        repository_url = string
        source_code_version = object({
          type = string
          value = string
        })
      }), {})
      image_repository = optional(object({
        image_configuration = optional(object({
          port = optional(string, null)
          runtime_environment_secrets = optional(map(string), {})
          runtime_environment_variables = optional(map(string), {})
          start_command = optional(string, null)
        }), {})
        image_identifier = string
        image_repository_type = string
      }), {})
    })
    instance_configuration = optional(object({
      cpu = optional(string, null)
      instance_role_arn = optional(string, null)
      memory = optional(string, null)
    }), {})
    network_configuration = optional(object({
      egress_configuration = optional(object({
        egress_type = optional(string, null)
        vpc_connector_arn = optional(string, null)
      }), {})
      ingress_configuration = optional(object({
        is_publicly_accessible = optional(bool, null)
      }), {})
    }), {})
    observability_configuration = optional(object({
      observability_enabled = optional(bool, null)
      trace_configuration = optional(object({
        vendor = optional(string, null)
      }), {})
    }), {})
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "apprunner_connections" {
  description = "Map of App Runner connections to create"
  type = map(object({
    connection_name = string
    provider_type = string
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "apprunner_vpc_connectors" {
  description = "Map of App Runner VPC connectors to create"
  type = map(object({
    vpc_connector_name = string
    subnets = list(string)
    security_groups = list(string)
    tags = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# Enhanced Copilot Configuration Variables
# ==============================================================================

variable "copilot_applications" {
  description = "Map of Copilot applications to create"
  type = map(object({
    name = string
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "copilot_environments" {
  description = "Map of Copilot environments to create"
  type = map(object({
    app = string
    name = string
    profile = optional(string, null)
    region = optional(string, null)
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "copilot_services" {
  description = "Map of Copilot services to create"
  type = map(object({
    app = string
    name = string
    type = string
    environment = optional(string, null)
    profile = optional(string, null)
    region = optional(string, null)
    tags = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# Enhanced Kubernetes Configuration Variables
# ==============================================================================

variable "kubernetes_namespaces" {
  description = "Map of Kubernetes namespaces to create"
  type = map(object({
    metadata = object({
      name = string
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
  }))
  default = {}
}

variable "kubernetes_deployments" {
  description = "Map of Kubernetes deployments to create"
  type = map(object({
    metadata = object({
      name = string
      namespace = optional(string, null)
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
    spec = object({
      replicas = optional(number, 1)
      selector = object({
        match_labels = map(string)
      })
      template = object({
        metadata = object({
          labels = map(string)
          annotations = optional(map(string), {})
        })
        spec = object({
          containers = list(object({
            name = string
            image = string
            ports = optional(list(object({
              container_port = number
              protocol = optional(string, "TCP")
            })), [])
            env = optional(list(object({
              name = string
              value = optional(string, null)
              value_from = optional(object({
                field_ref = optional(object({
                  field_path = string
                }), {})
                secret_key_ref = optional(object({
                  name = string
                  key = string
                }), {})
                config_map_key_ref = optional(object({
                  name = string
                  key = string
                }), {})
              }), {})
            })), [])
            resources = optional(object({
              limits = optional(map(string), {})
              requests = optional(map(string), {})
            }), {})
            liveness_probe = optional(object({
              http_get = optional(object({
                path = string
                port = number
              }), {})
              tcp_socket = optional(object({
                port = number
              }), {})
              exec = optional(object({
                command = list(string)
              }), {})
              initial_delay_seconds = optional(number, null)
              period_seconds = optional(number, null)
              timeout_seconds = optional(number, null)
              failure_threshold = optional(number, null)
              success_threshold = optional(number, null)
            }), {})
            readiness_probe = optional(object({
              http_get = optional(object({
                path = string
                port = number
              }), {})
              tcp_socket = optional(object({
                port = number
              }), {})
              exec = optional(object({
                command = list(string)
              }), {})
              initial_delay_seconds = optional(number, null)
              period_seconds = optional(number, null)
              timeout_seconds = optional(number, null)
              failure_threshold = optional(number, null)
              success_threshold = optional(number, null)
            }), {})
          }))
          volumes = optional(list(object({
            name = string
            empty_dir = optional(object({}), {})
            persistent_volume_claim = optional(object({
              claim_name = string
              read_only = optional(bool, null)
            }), {})
            config_map = optional(object({
              name = string
              items = optional(list(object({
                key = string
                path = string
                mode = optional(number, null)
              })), [])
            }), {})
            secret = optional(object({
              secret_name = string
              items = optional(list(object({
                key = string
                path = string
                mode = optional(number, null)
              })), [])
            }), {})
          })), [])
        })
      })
    })
  }))
  default = {}
}

variable "kubernetes_services" {
  description = "Map of Kubernetes services to create"
  type = map(object({
    metadata = object({
      name = string
      namespace = optional(string, null)
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
    spec = object({
      type = optional(string, "ClusterIP")
      selector = optional(map(string), {})
      ports = list(object({
        port = number
        target_port = optional(number, null)
        protocol = optional(string, "TCP")
        name = optional(string, null)
        node_port = optional(number, null)
      }))
      external_ips = optional(list(string), [])
      load_balancer_ip = optional(string, null)
      load_balancer_source_ranges = optional(list(string), [])
      external_name = optional(string, null)
      external_traffic_policy = optional(string, null)
      health_check_node_port = optional(number, null)
      publish_not_ready_addresses = optional(bool, null)
      session_affinity = optional(string, null)
      session_affinity_config = optional(object({
        client_ip = optional(object({
          timeout_seconds = number
        }), {})
      }), {})
    })
  }))
  default = {}
}

variable "kubernetes_config_maps" {
  description = "Map of Kubernetes config maps to create"
  type = map(object({
    metadata = object({
      name = string
      namespace = optional(string, null)
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
    data = optional(map(string), {})
    binary_data = optional(map(string), {})
  }))
  default = {}
}

variable "kubernetes_secrets" {
  description = "Map of Kubernetes secrets to create"
  type = map(object({
    metadata = object({
      name = string
      namespace = optional(string, null)
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
    type = optional(string, "Opaque")
    data = optional(map(string), {})
    string_data = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# Enhanced Helm Configuration Variables
# ==============================================================================

variable "helm_releases" {
  description = "Map of Helm releases to create"
  type = map(object({
    name = string
    repository = optional(string, null)
    chart = string
    version = optional(string, null)
    namespace = optional(string, null)
    create_namespace = optional(bool, null)
    verify = optional(bool, null)
    keyring = optional(string, null)
    timeout = optional(number, null)
    disable_webhooks = optional(bool, null)
    disable_crd_hooks = optional(bool, null)
    reuse_values = optional(bool, null)
    reset_values = optional(bool, null)
    force_update = optional(bool, null)
    recreate_pods = optional(bool, null)
    cleanup_on_fail = optional(bool, null)
    max_history = optional(number, null)
    atomic = optional(bool, null)
    skip_crds = optional(bool, null)
    render_subchart_notes = optional(bool, null)
    disable_openapi_validation = optional(bool, null)
    wait = optional(bool, null)
    wait_for_jobs = optional(bool, null)
    dependency_update = optional(bool, null)
    replace = optional(bool, null)
    description = optional(string, null)
    postrender = optional(object({
      binary_path = string
    }), {})
    set = optional(list(object({
      name = string
      value = string
      type = optional(string, null)
    })), [])
    set_sensitive = optional(list(object({
      name = string
      value = string
      type = optional(string, null)
    })), [])
    set_string = optional(list(object({
      name = string
      value = string
    })), [])
    values = optional(list(string), [])
    repository_username = optional(string, null)
    repository_password = optional(string, null)
    repository_ca_file = optional(string, null)
    repository_cert_file = optional(string, null)
    repository_key_file = optional(string, null)
    repository_insecure = optional(bool, null)
    devel = optional(bool, null)
    debug = optional(bool, null)
    chart = string
    version = optional(string, null)
    namespace = optional(string, null)
    create_namespace = optional(bool, null)
    verify = optional(bool, null)
    keyring = optional(string, null)
    timeout = optional(number, null)
    disable_webhooks = optional(bool, null)
    disable_crd_hooks = optional(bool, null)
    reuse_values = optional(bool, null)
    reset_values = optional(bool, null)
    force_update = optional(bool, null)
    recreate_pods = optional(bool, null)
    cleanup_on_fail = optional(bool, null)
    max_history = optional(number, null)
    atomic = optional(bool, null)
    skip_crds = optional(bool, null)
    render_subchart_notes = optional(bool, null)
    disable_openapi_validation = optional(bool, null)
    wait = optional(bool, null)
    wait_for_jobs = optional(bool, null)
    dependency_update = optional(bool, null)
    replace = optional(bool, null)
    description = optional(string, null)
    postrender = optional(object({
      binary_path = string
    }), {})
    set = optional(list(object({
      name = string
      value = string
      type = optional(string, null)
    })), [])
    set_sensitive = optional(list(object({
      name = string
      value = string
      type = optional(string, null)
    })), [])
    set_string = optional(list(object({
      name = string
      value = string
    })), [])
    values = optional(list(string), [])
    repository_username = optional(string, null)
    repository_password = optional(string, null)
    repository_ca_file = optional(string, null)
    repository_cert_file = optional(string, null)
    repository_key_file = optional(string, null)
    repository_insecure = optional(bool, null)
    devel = optional(bool, null)
    debug = optional(bool, null)
  }))
  default = {}
} 