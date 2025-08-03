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
# Enhanced VPC Variables
# ==============================================================================

variable "vpc_config" {
  description = "VPC configuration with enhanced options"
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
    
    # Enhanced VPC Configuration
    enable_dhcp_options = optional(bool, false)
    dhcp_options_domain_name = optional(string, null)
    dhcp_options_domain_name_servers = optional(list(string), ["AmazonProvidedDNS"])
    dhcp_options_ntp_servers = optional(list(string), [])
    dhcp_options_netbios_name_servers = optional(list(string), [])
    dhcp_options_netbios_node_type = optional(string, null)
    
    # Enhanced NAT Gateway Configuration
    nat_gateway_destination_cidr_block = optional(string, "0.0.0.0/0")
    nat_eip_tags = optional(map(string), {})
    nat_gateway_tags = optional(map(string), {})
    
    # Enhanced Flow Log Configuration
    flow_log_cloudwatch_iam_role_arn = optional(string, null)
    flow_log_cloudwatch_log_group_kms_key_id = optional(string, null)
    flow_log_max_aggregation_interval = optional(number, 600)
    flow_log_traffic_type = optional(string, "ALL")
    
    # Enhanced Subnet Tags
    public_subnet_tags = optional(map(string), {})
    private_subnet_tags = optional(map(string), {})
    database_subnet_tags = optional(map(string), {})
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
# Enhanced Security Groups Configuration
# ==============================================================================

variable "security_groups_config" {
  description = "Global security groups configuration"
  type = object({
    revoke_rules_on_delete = optional(bool, false)
  })
  default = {}
}

variable "security_groups" {
  description = "Security groups configuration with enhanced options"
  type = map(object({
    name = string
    description = string
    vpc_id = optional(string, null)
    revoke_rules_on_delete = optional(bool, null)
    ingress_rules = optional(list(object({
      description = optional(string, "")
      from_port = number
      to_port = number
      protocol = string
      cidr_blocks = optional(list(string), [])
      security_groups = optional(list(string), [])
      self = optional(bool, false)
      ipv6_cidr_blocks = optional(list(string), [])
      prefix_list_ids = optional(list(string), [])
    })), [])
    egress_rules = optional(list(object({
      description = optional(string, "")
      from_port = number
      to_port = number
      protocol = string
      cidr_blocks = optional(list(string), ["0.0.0.0/0"])
      security_groups = optional(list(string), [])
      self = optional(bool, false)
      ipv6_cidr_blocks = optional(list(string), [])
      prefix_list_ids = optional(list(string), [])
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

# ==============================================================================
# Enhanced EKS Variables
# ==============================================================================

variable "eks_config" {
  description = "EKS cluster configuration with enhanced options"
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
    
    # Enhanced EKS Configuration
    cluster_encryption_config = optional(list(object({
      provider_key_arn = string
      resources = list(string)
    })), [])
    
    # Enhanced Security Group Configuration
    cluster_security_group_additional_rules = optional(map(object({
      description = string
      protocol = string
      from_port = number
      to_port = number
      type = string
      cidr_blocks = optional(list(string), [])
      security_groups = optional(list(string), [])
      self = optional(bool, false)
      source_node_security_group = optional(bool, false)
      source_cluster_security_group = optional(bool, false)
    })), {})
    
    node_security_group_additional_rules = optional(map(object({
      description = string
      protocol = string
      from_port = number
      to_port = number
      type = string
      cidr_blocks = optional(list(string), [])
      security_groups = optional(list(string), [])
      self = optional(bool, false)
      source_node_security_group = optional(bool, false)
      source_cluster_security_group = optional(bool, false)
    })), {})
    
    # Enhanced Add-ons Configuration
    cluster_addons = optional(map(object({
      most_recent = optional(bool, true)
      before_compute = optional(bool, false)
      configuration_values = optional(string, "")
      service_account_role_arn = optional(string, "")
    })), {})
  })
  default = {}
}

variable "eks_node_groups" {
  description = "EKS node groups configuration with enhanced options"
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
    
    # Enhanced Node Group Configuration
    use_name_prefix = optional(bool, true)
    use_custom_launch_template = optional(bool, false)
    create_launch_template = optional(bool, false)
    launch_template_name = optional(string, null)
    launch_template_use_name_prefix = optional(bool, true)
    launch_template_description = optional(string, null)
    
    # Enhanced IAM Configuration
    iam_role_name = optional(string, null)
    iam_role_use_name_prefix = optional(bool, true)
    iam_role_description = optional(string, null)
    iam_role_path = optional(string, "/")
    iam_role_permissions_boundary = optional(string, null)
    iam_role_additional_policies = optional(list(string), [])
    
    # Enhanced Security Configuration
    vpc_security_group_ids = optional(list(string), [])
    cluster_security_group_id = optional(string, null)
    
    # Enhanced Monitoring Configuration
    enable_monitoring = optional(bool, true)
    enable_bootstrap_user_data = optional(bool, true)
    bootstrap_extra_args = optional(string, null)
    post_bootstrap_user_data = optional(string, null)
    pre_bootstrap_user_data = optional(string, null)
    
    # Enhanced Networking Configuration
    subnet_ids = optional(list(string), [])
    private_ipv4_address = optional(string, null)
    
    # Enhanced Storage Configuration
    block_device_mappings = optional(list(object({
      device_name = string
      ebs = optional(object({
        delete_on_termination = optional(bool, true)
        encrypted = optional(bool, true)
        iops = optional(number, null)
        kms_key_id = optional(string, null)
        snapshot_id = optional(string, null)
        throughput = optional(number, null)
        volume_size = optional(number, null)
        volume_type = optional(string, "gp3")
      }), {})
    })), [])
    ebs_optimized = optional(bool, true)
    enable_spot_instance = optional(bool, false)
    spot_price = optional(string, null)
    
    # Enhanced Scaling Configuration
    scaling_config = optional(object({
      desired_size = optional(number, 2)
      max_size = optional(number, 5)
      min_size = optional(number, 1)
    }), {})
    
    # Additional Configuration
    additional_configuration = optional(map(any), null)
  }))
  default = {}
}

variable "eks_fargate_profiles" {
  description = "EKS Fargate profiles configuration with enhanced options"
  type = map(object({
    name = string
    selectors = list(object({
      namespace = string
      labels = optional(map(string), {})
    }))
    subnets = optional(list(string), [])
    tags = optional(map(string), {})
    
    # Enhanced Fargate Configuration
    iam_role_name = optional(string, null)
    iam_role_use_name_prefix = optional(bool, true)
    iam_role_description = optional(string, null)
    iam_role_path = optional(string, "/")
    iam_role_permissions_boundary = optional(string, null)
    iam_role_additional_policies = optional(list(string), [])
    
    # Additional Configuration
    additional_configuration = optional(map(any), null)
  }))
  default = {}
}

# ==============================================================================
# Enhanced ECR Variables
# ==============================================================================

variable "ecr_repositories" {
  description = "ECR repositories configuration with enhanced options"
  type = map(object({
    name = string
    image_tag_mutability = optional(string, "MUTABLE")
    scan_on_push = optional(bool, true)
    encryption_type = optional(string, "AES256")
    kms_key_id = optional(string, null)
    force_delete = optional(bool, false)
    registry_id = optional(string, null)
    repository_policy = optional(string, null)
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

variable "ecr_vulnerability_scanning_config" {
  description = "ECR vulnerability scanning configuration"
  type = object({
    scan_type = optional(string, "ENHANCED")
    rules = optional(list(object({
      scan_frequency = optional(string, "CONTINUOUS_SCAN")
      repository_filter = object({
        filter = string
        filter_type = string
      })
    })), [{
      scan_frequency = "CONTINUOUS_SCAN"
      repository_filter = {
        filter = "*"
        filter_type = "WILDCARD"
      }
    }])
  })
  default = {}
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
# Enhanced Monitoring and Logging Variables
# ==============================================================================

variable "enable_cloudwatch_container_insights" {
  description = "Enable CloudWatch Container Insights for EKS"
  type        = bool
  default     = true
}

variable "cloudwatch_container_insights_config" {
  description = "CloudWatch Container Insights configuration"
  type = object({
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
  })
  default = {}
}

variable "enable_aws_load_balancer_controller" {
  description = "Enable AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "aws_load_balancer_controller_config" {
  description = "AWS Load Balancer Controller configuration"
  type = object({
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
  })
  default = {}
}

variable "enable_metrics_server" {
  description = "Enable Metrics Server"
  type        = bool
  default     = true
}

variable "metrics_server_config" {
  description = "Metrics Server configuration"
  type = object({
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
  })
  default = {}
}

variable "enable_cluster_autoscaler" {
  description = "Enable Cluster Autoscaler"
  type        = bool
  default     = false
}

variable "cluster_autoscaler_config" {
  description = "Cluster Autoscaler configuration"
  type = object({
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
  })
  default = {}
}

# ==============================================================================
# Enhanced Backup and Disaster Recovery Variables
# ==============================================================================

variable "enable_velero_backup" {
  description = "Enable Velero backup solution"
  type        = bool
  default     = false
}

variable "velero_backup_config" {
  description = "Velero backup configuration with enhanced options"
  type = object({
    backup_location_bucket = optional(string, "")
    backup_location_region = optional(string, "")
    schedule = optional(string, "0 2 * * *") # Daily at 2 AM
    retention_days = optional(number, 30)
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
  })
  default = {}
}

# ==============================================================================
# Enhanced Network Policies Variables
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

variable "network_policy_config" {
  description = "Network policy configuration"
  type = object({
    calico = optional(object({
      version = optional(string, null)
      timeout = optional(number, 300)
      wait = optional(bool, true)
      atomic = optional(bool, false)
      cleanup_on_fail = optional(bool, false)
      additional_settings = optional(map(string), {})
    }), {})
    cilium = optional(object({
      version = optional(string, null)
      timeout = optional(number, 300)
      wait = optional(bool, true)
      atomic = optional(bool, false)
      cleanup_on_fail = optional(bool, false)
      additional_settings = optional(map(string), {})
    }), {})
  })
  default = {}
}

# ==============================================================================
# Enhanced Monitoring and Observability Variables
# ==============================================================================

variable "enable_prometheus_monitoring" {
  description = "Enable Prometheus monitoring stack"
  type        = bool
  default     = false
}

variable "prometheus_config" {
  description = "Prometheus configuration with enhanced options"
  type = object({
    grafana_admin_password = string
    retention_days = optional(number, 15)
    storage_size = optional(string, "50Gi")
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
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

variable "kubernetes_dashboard_config" {
  description = "Kubernetes Dashboard configuration"
  type = object({
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
  })
  default = {}
}

variable "enable_jaeger_tracing" {
  description = "Enable Jaeger distributed tracing"
  type        = bool
  default     = false
}

variable "jaeger_config" {
  description = "Jaeger configuration with enhanced options"
  type = object({
    elasticsearch_url = string
    elasticsearch_username = string
    elasticsearch_password = string
    version = optional(string, null)
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
    additional_settings = optional(map(string), {})
  })
  default = {
    elasticsearch_url = "http://elasticsearch:9200"
    elasticsearch_username = "elastic"
    elasticsearch_password = "changeme"
  }
}

# ==============================================================================
# Legacy Variables (for backward compatibility)
# ==============================================================================

# These variables are kept for backward compatibility but are now deprecated
# in favor of the enhanced configurations above

variable "ecs_clusters" {
  description = "Map of ECS clusters to create (DEPRECATED - use enhanced EKS configuration)"
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
  description = "Map of ECS services to create (DEPRECATED - use enhanced EKS configuration)"
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
    }), null)
    deployment_controller = optional(object({
      type = string
    }), null)
    placement_constraints = optional(list(object({
      type = string
      expression = optional(string, null)
    })), [])
    placement_strategy = optional(list(object({
      type = string
      field = optional(string, null)
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecs_task_definitions" {
  description = "Map of ECS task definitions to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    family = string
    network_mode = optional(string, "awsvpc")
    requires_compatibilities = optional(list(string), ["FARGATE"])
    cpu = optional(number, 256)
    memory = optional(number, 512)
    execution_role_arn = optional(string, null)
    task_role_arn = optional(string, null)
    container_definitions = list(object({
      name = string
      image = string
      cpu = optional(number, null)
      memory = optional(number, null)
      memory_reservation = optional(number, null)
      essential = optional(bool, true)
      port_mappings = optional(list(object({
        container_port = number
        host_port = optional(number, null)
        protocol = optional(string, "tcp")
      })), [])
      environment = optional(list(object({
        name = string
        value = string
      })), [])
      secrets = optional(list(object({
        name = string
        value_from = string
      })), [])
      log_configuration = optional(object({
        log_driver = string
        options = optional(map(string), {})
        secret_options = optional(list(object({
          name = string
          value_from = string
        })), [])
      }), null)
      mount_points = optional(list(object({
        source_volume = string
        container_path = string
        read_only = optional(bool, false)
      })), [])
      volumes_from = optional(list(object({
        source_container = string
        read_only = optional(bool, false)
      })), [])
      depends_on = optional(list(object({
        container_name = string
        condition = string
      })), [])
      start_timeout = optional(number, null)
      stop_timeout = optional(number, null)
      user = optional(string, null)
      working_directory = optional(string, null)
      disable_networking = optional(bool, null)
      privileged = optional(bool, null)
      readonly_root_filesystem = optional(bool, null)
      dns_servers = optional(list(string), [])
      dns_search_domains = optional(list(string), [])
      extra_hosts = optional(list(object({
        hostname = string
        ip_address = string
      })), [])
      docker_security_options = optional(list(string), [])
      interactive = optional(bool, null)
      pseudo_terminal = optional(bool, null)
      system_controls = optional(list(object({
        namespace = string
        value = string
      })), [])
    }))
    volumes = optional(list(object({
      name = string
      host_path = optional(string, null)
      docker_volume_configuration = optional(object({
        scope = string
        autoprovision = optional(bool, null)
        driver = optional(string, null)
        driver_opts = optional(map(string), {})
        labels = optional(map(string), {})
      }), null)
      efs_volume_configuration = optional(object({
        file_system_id = string
        root_directory = optional(string, null)
        transit_encryption = optional(string, null)
        transit_encryption_port = optional(number, null)
        authorization_config = optional(object({
          access_point_id = optional(string, null)
          iam = optional(bool, null)
        }), null)
      }), null)
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecs_capacity_providers" {
  description = "Map of ECS capacity providers to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    name = string
    auto_scaling_group_provider = object({
      auto_scaling_group_arn = string
      managed_termination_protection = optional(string, "ENABLED")
      managed_scaling = optional(object({
        maximum_scaling_step_size = optional(number, 1000)
        minimum_scaling_step_size = optional(number, 1)
        status = optional(string, "ENABLED")
        target_capacity = optional(number, 100)
      }), {})
    })
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecs_cluster_capacity_providers" {
  description = "Map of ECS cluster capacity providers to create (DEPRECATED - use enhanced EKS configuration)"
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

variable "eks_clusters" {
  description = "Map of EKS clusters to create (DEPRECATED - use enhanced eks_config)"
  type = map(object({
    name = string
    version = optional(string, "1.28")
    role_arn = optional(string, null)
    vpc_config = object({
      subnet_ids = list(string)
      security_group_ids = optional(list(string), [])
      endpoint_private_access = optional(bool, true)
      endpoint_public_access = optional(bool, true)
      public_access_cidrs = optional(list(string), ["0.0.0.0/0"])
    })
    enabled_cluster_log_types = optional(list(string), ["api", "audit", "authenticator", "controllerManager", "scheduler"])
    encryption_config = optional(list(object({
      provider_key_arn = string
      resources = list(string)
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "eks_addons" {
  description = "Map of EKS add-ons to create (DEPRECATED - use enhanced eks_config.cluster_addons)"
  type = map(object({
    cluster_name = string
    addon_name = string
    addon_version = optional(string, null)
    resolve_conflicts = optional(string, "OVERWRITE")
    service_account_role_arn = optional(string, null)
    configuration_values = optional(string, "")
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "ecr_lifecycle_policies" {
  description = "Map of ECR lifecycle policies to create (DEPRECATED - use enhanced ecr_repositories)"
  type = map(object({
    repository = string
    policy = string
  }))
  default = {}
}

variable "ecr_registry_policy" {
  description = "ECR registry policy (DEPRECATED - use enhanced ecr_repositories)"
  type        = string
  default     = null
}

variable "ecr_registry_scanning_configuration" {
  description = "ECR registry scanning configuration (DEPRECATED - use enhanced ecr_vulnerability_scanning_config)"
  type = object({
    scan_type = optional(string, "ENHANCED")
    rules = optional(list(object({
      scan_frequency = optional(string, "CONTINUOUS_SCAN")
      repository_filter = object({
        filter = string
        filter_type = string
      })
    })), [])
  })
  default = {}
}

variable "ecr_repository_policies" {
  description = "Map of ECR repository policies to create (DEPRECATED - use enhanced ecr_repositories)"
  type = map(object({
    repository = string
    policy = string
  }))
  default = {}
}

variable "apprunner_services" {
  description = "Map of App Runner services to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    service_name = string
    source_configuration = object({
      auto_deployments_enabled = optional(bool, true)
      authentication_configuration = optional(object({
        access_role_arn = optional(string, null)
        connection_arn = optional(string, null)
      }), null)
      code_repository = optional(object({
        code_configuration = optional(object({
          configuration_source = string
          configuration_values = optional(string, null)
        }), null)
        source_code_version = object({
          type = string
          value = string
        })
        repository_url = string
      }), null)
      image_repository = optional(object({
        image_configuration = optional(object({
          port = optional(string, null)
          runtime_environment_variables = optional(map(string), {})
          runtime_environment_secrets = optional(map(string), {})
          start_command = optional(string, null)
        }), null)
        image_identifier = string
        image_repository_type = string
      }), null)
    })
    instance_configuration = optional(object({
      cpu = optional(string, "1024")
      memory = optional(string, "2048")
      instance_role_arn = optional(string, null)
    }), {})
    network_configuration = optional(object({
      egress_configuration = object({
        egress_type = string
        vpc_connector_arn = optional(string, null)
      })
      ingress_configuration = optional(object({
        is_publicly_accessible = optional(bool, true)
      }), null)
    }), null)
    observability_configuration = optional(object({
      observability_enabled = optional(bool, true)
      trace_configuration = optional(object({
        vendor = string
      }), null)
    }), null)
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "apprunner_connections" {
  description = "Map of App Runner connections to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    connection_name = string
    provider_type = string
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "apprunner_vpc_connectors" {
  description = "Map of App Runner VPC connectors to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    vpc_connector_name = string
    subnets = list(string)
    security_groups = list(string)
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "copilot_applications" {
  description = "Map of Copilot applications to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    name = string
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "copilot_environments" {
  description = "Map of Copilot environments to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    name = string
    app = string
    type = string
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "copilot_services" {
  description = "Map of Copilot services to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    name = string
    app = string
    environment = string
    type = string
    tags = optional(map(string), {})
  }))
  default = {}
}

variable "kubernetes_namespaces" {
  description = "Map of Kubernetes namespaces to create (DEPRECATED - use enhanced EKS configuration)"
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
  description = "Map of Kubernetes deployments to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    metadata = object({
      name = string
      namespace = string
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
                  api_version = optional(string, "v1")
                  field_path = string
                }), null)
                resource_field_ref = optional(object({
                  container_name = optional(string, null)
                  divisor = optional(string, null)
                  resource = string
                }), null)
                config_map_key_ref = optional(object({
                  name = optional(string, null)
                  key = string
                }), null)
                secret_key_ref = optional(object({
                  name = optional(string, null)
                  key = string
                }), null)
              }), null)
            })), [])
            resources = optional(object({
              limits = optional(map(string), {})
              requests = optional(map(string), {})
            }), {})
            liveness_probe = optional(object({
              http_get = optional(object({
                path = string
                port = number
              }), null)
              tcp_socket = optional(object({
                port = number
              }), null)
              initial_delay_seconds = optional(number, null)
              period_seconds = optional(number, null)
              timeout_seconds = optional(number, null)
              failure_threshold = optional(number, null)
              success_threshold = optional(number, null)
            }), null)
            readiness_probe = optional(object({
              http_get = optional(object({
                path = string
                port = number
              }), null)
              tcp_socket = optional(object({
                port = number
              }), null)
              initial_delay_seconds = optional(number, null)
              period_seconds = optional(number, null)
              timeout_seconds = optional(number, null)
              failure_threshold = optional(number, null)
              success_threshold = optional(number, null)
            }), null)
            volume_mounts = optional(list(object({
              name = string
              mount_path = string
              read_only = optional(bool, false)
            })), [])
          }))
          volumes = optional(list(object({
            name = string
            empty_dir = optional(object({}), null)
            config_map = optional(object({
              name = string
              items = optional(list(object({
                key = string
                path = string
              })), [])
            }), null)
            secret = optional(object({
              secret_name = string
              items = optional(list(object({
                key = string
                path = string
              })), [])
            }), null)
            persistent_volume_claim = optional(object({
              claim_name = string
              read_only = optional(bool, false)
            }), null)
          })), [])
        })
      })
    })
  }))
  default = {}
}

variable "kubernetes_services" {
  description = "Map of Kubernetes services to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    metadata = object({
      name = string
      namespace = string
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
    spec = object({
      selector = map(string)
      type = optional(string, "ClusterIP")
      ports = list(object({
        port = number
        target_port = number
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
        }), null)
      }), null)
    })
  }))
  default = {}
}

variable "kubernetes_config_maps" {
  description = "Map of Kubernetes ConfigMaps to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    metadata = object({
      name = string
      namespace = string
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
    data = optional(map(string), {})
    binary_data = optional(map(string), {})
  }))
  default = {}
}

variable "kubernetes_secrets" {
  description = "Map of Kubernetes Secrets to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    metadata = object({
      name = string
      namespace = string
      labels = optional(map(string), {})
      annotations = optional(map(string), {})
    })
    type = optional(string, "Opaque")
    data = optional(map(string), {})
    string_data = optional(map(string), {})
  }))
  default = {}
}

variable "helm_releases" {
  description = "Map of Helm releases to create (DEPRECATED - use enhanced EKS configuration)"
  type = map(object({
    name = string
    repository = string
    chart = string
    version = optional(string, null)
    namespace = string
    create_namespace = optional(bool, false)
    values = optional(list(string), [])
    set = optional(list(object({
      name = string
      value = string
    })), [])
    timeout = optional(number, 300)
    wait = optional(bool, true)
    atomic = optional(bool, false)
    cleanup_on_fail = optional(bool, false)
  }))
  default = {}
} 