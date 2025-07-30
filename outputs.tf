# ==============================================================================
# VPC Outputs
# ==============================================================================

output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "vpc_arn" {
  description = "The ARN of the VPC"
  value       = module.vpc.vpc_arn
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "database_subnets" {
  description = "List of IDs of database subnets"
  value       = module.vpc.database_subnets
}

output "private_subnet_arns" {
  description = "List of ARNs of private subnets"
  value       = module.vpc.private_subnet_arns
}

output "public_subnet_arns" {
  description = "List of ARNs of public subnets"
  value       = module.vpc.public_subnet_arns
}

output "database_subnet_arns" {
  description = "List of ARNs of database subnets"
  value       = module.vpc.database_subnet_arns
}

output "private_subnets_cidr_blocks" {
  description = "List of cidr_blocks of private subnets"
  value       = module.vpc.private_subnets_cidr_blocks
}

output "public_subnets_cidr_blocks" {
  description = "List of cidr_blocks of public subnets"
  value       = module.vpc.public_subnets_cidr_blocks
}

output "database_subnets_cidr_blocks" {
  description = "List of cidr_blocks of database subnets"
  value       = module.vpc.database_subnets_cidr_blocks
}

output "nat_public_ips" {
  description = "List of public Elastic IPs created for NAT Gateway"
  value       = module.vpc.nat_public_ips
}

output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs"
  value       = module.vpc.nat_gateway_ids
}

output "nat_instance_ids" {
  description = "List of NAT Instance IDs"
  value       = module.vpc.nat_instance_ids
}

output "nat_instance_public_ips" {
  description = "List of public Elastic IPs created for NAT Gateway"
  value       = module.vpc.nat_instance_public_ips
}

output "igw_id" {
  description = "The ID of the Internet Gateway"
  value       = module.vpc.igw_id
}

output "igw_arn" {
  description = "The ARN of the Internet Gateway"
  value       = module.vpc.igw_arn
}

output "default_route_table_id" {
  description = "The ID of the default route table"
  value       = module.vpc.default_route_table_id
}

output "private_route_table_ids" {
  description = "List of IDs of private route tables"
  value       = module.vpc.private_route_table_ids
}

output "public_route_table_ids" {
  description = "List of IDs of public route tables"
  value       = module.vpc.public_route_table_ids
}

output "database_route_table_ids" {
  description = "List of IDs of database route tables"
  value       = module.vpc.database_route_table_ids
}

# ==============================================================================
# Security Groups Outputs
# ==============================================================================

output "eks_cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = length(var.eks_node_groups) > 0 ? aws_security_group.eks_cluster[0].id : null
}

output "eks_nodes_security_group_id" {
  description = "Security group ID attached to the EKS nodes"
  value       = length(var.eks_node_groups) > 0 ? aws_security_group.eks_nodes[0].id : null
}

output "custom_security_group_ids" {
  description = "Map of custom security group IDs"
  value       = { for k, v in aws_security_group.custom : k => v.id }
}

# ==============================================================================
# EKS Outputs
# ==============================================================================

output "cluster_id" {
  description = "EKS cluster ID"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_id : null
}

output "cluster_arn" {
  description = "The Amazon Resource Name (ARN) of the cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_arn : null
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_certificate_authority_data : null
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_endpoint : null
}

output "cluster_iam_role_name" {
  description = "IAM role name associated with EKS cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_iam_role_name : null
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN associated with EKS cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_iam_role_arn : null
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_oidc_issuer_url : null
}

output "cluster_platform_version" {
  description = "Platform version for the cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_platform_version : null
}

output "cluster_status" {
  description = "Status of the EKS cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_status : null
}

output "cluster_primary_security_group_id" {
  description = "Cluster security group that was created by Amazon EKS for the cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_primary_security_group_id : null
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_security_group_id : null
}

output "cluster_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the cluster security group"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_security_group_arn : null
}

output "node_security_group_id" {
  description = "ID of the node shared security group"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].node_security_group_id : null
}

output "node_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the node shared security group"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].node_security_group_arn : null
}

output "cluster_cloudwatch_log_group_arn" {
  description = "Amazon Resource Name (ARN) of CloudWatch log group"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_cloudwatch_log_group_arn : null
}

output "cluster_cloudwatch_log_group_name" {
  description = "Name of CloudWatch log group"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].cluster_cloudwatch_log_group_name : null
}

output "eks_managed_node_groups" {
  description = "Map of EKS managed node groups"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].eks_managed_node_groups : {}
}

output "eks_managed_node_groups_autoscaling_group_names" {
  description = "List of the autoscaling group names created by EKS managed node groups"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].eks_managed_node_groups_autoscaling_group_names : []
}

output "fargate_profiles" {
  description = "Map of EKS Fargate profiles"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].fargate_profiles : {}
}

output "fargate_profile_ids" {
  description = "EKS Cluster's Fargate Profile IDs"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].fargate_profile_ids : []
}

output "fargate_profile_arns" {
  description = "EKS Cluster's Fargate Profile ARNs"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].fargate_profile_arns : []
}

output "fargate_profile_statuses" {
  description = "EKS Cluster's Fargate Profile statuses"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].fargate_profile_statuses : []
}

# ==============================================================================
# ECR Outputs
# ==============================================================================

output "ecr_repository_urls" {
  description = "Map of ECR repository URLs"
  value       = { for k, v in aws_ecr_repository.repositories : k => v.repository_url }
}

output "ecr_repository_arns" {
  description = "Map of ECR repository ARNs"
  value       = { for k, v in aws_ecr_repository.repositories : k => v.arn }
}

output "ecr_repository_names" {
  description = "Map of ECR repository names"
  value       = { for k, v in aws_ecr_repository.repositories : k => v.name }
}

output "ecr_registry_id" {
  description = "Registry ID"
  value       = length(aws_ecr_repository.repositories) > 0 ? aws_ecr_repository.repositories[keys(aws_ecr_repository.repositories)[0]].registry_id : null
}

output "ecr_registry_url" {
  description = "Registry URL"
  value       = length(aws_ecr_repository.repositories) > 0 ? "${aws_ecr_repository.repositories[keys(aws_ecr_repository.repositories)[0]].registry_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com" : null
}

# ==============================================================================
# Kubernetes Configuration Outputs
# ==============================================================================

output "kubeconfig" {
  description = "Base64 encoded kubeconfig"
  value       = length(var.eks_node_groups) > 0 ? base64encode(module.eks[0].kubeconfig) : null
  sensitive   = true
}

output "kubeconfig_filename" {
  description = "The filename of the generated kubectl config"
  value       = length(var.eks_node_groups) > 0 ? module.eks[0].kubeconfig_filename : null
}

# ==============================================================================
# Helm Release Outputs
# ==============================================================================

output "cloudwatch_container_insights_status" {
  description = "Status of CloudWatch Container Insights Helm release"
  value       = var.enable_cloudwatch_container_insights && length(var.eks_node_groups) > 0 ? helm_release.cloudwatch_container_insights[0].status : null
}

output "aws_load_balancer_controller_status" {
  description = "Status of AWS Load Balancer Controller Helm release"
  value       = var.enable_aws_load_balancer_controller && length(var.eks_node_groups) > 0 ? helm_release.aws_load_balancer_controller[0].status : null
}

output "metrics_server_status" {
  description = "Status of Metrics Server Helm release"
  value       = var.enable_metrics_server && length(var.eks_node_groups) > 0 ? helm_release.metrics_server[0].status : null
}

output "cluster_autoscaler_status" {
  description = "Status of Cluster Autoscaler Helm release"
  value       = var.enable_cluster_autoscaler && length(var.eks_node_groups) > 0 ? helm_release.cluster_autoscaler[0].status : null
}

output "calico_status" {
  description = "Status of Calico Helm release"
  value       = var.enable_network_policies && var.network_policy_provider == "calico" && length(var.eks_node_groups) > 0 ? helm_release.calico[0].status : null
}

output "cilium_status" {
  description = "Status of Cilium Helm release"
  value       = var.enable_network_policies && var.network_policy_provider == "cilium" && length(var.eks_node_groups) > 0 ? helm_release.cilium[0].status : null
}

output "velero_status" {
  description = "Status of Velero backup solution"
  value       = var.enable_velero_backup && length(var.eks_node_groups) > 0 ? "enabled" : "disabled"
}

# ==============================================================================
# Monitoring and Observability Outputs
# ==============================================================================

output "prometheus_status" {
  description = "Status of Prometheus monitoring stack"
  value       = var.enable_prometheus_monitoring && length(var.eks_node_groups) > 0 ? "enabled" : "disabled"
}

output "kubernetes_dashboard_status" {
  description = "Status of Kubernetes Dashboard"
  value       = var.enable_kubernetes_dashboard && length(var.eks_node_groups) > 0 ? "enabled" : "disabled"
}

output "jaeger_status" {
  description = "Status of Jaeger distributed tracing"
  value       = var.enable_jaeger_tracing && length(var.eks_node_groups) > 0 ? "enabled" : "disabled"
}

output "ecr_vulnerability_scanning_status" {
  description = "Status of ECR vulnerability scanning"
  value       = var.enable_ecr_vulnerability_scanning ? "enabled" : "disabled"
}

output "ecr_pull_through_cache_rules" {
  description = "ECR pull-through cache rules"
  value       = var.ecr_pull_through_cache_rules
}

# ==============================================================================
# Common Outputs
# ==============================================================================

output "tags" {
  description = "A map of tags assigned to the resource"
  value       = local.common_tags
}

output "region" {
  description = "AWS region"
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "caller_arn" {
  description = "ARN of the caller"
  value       = data.aws_caller_identity.current.arn
}

output "caller_user" {
  description = "Unique identifier of the calling entity"
  value       = data.aws_caller_identity.current.user_id
} 