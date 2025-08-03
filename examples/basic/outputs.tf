# ==============================================================================
# Enhanced Basic Example Outputs
# ==============================================================================

output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.enhanced_container_infrastructure.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.enhanced_container_infrastructure.vpc_cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.enhanced_container_infrastructure.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.enhanced_container_infrastructure.public_subnets
}

output "database_subnets" {
  description = "List of IDs of database subnets"
  value       = module.enhanced_container_infrastructure.database_subnets
}

output "cluster_id" {
  description = "EKS cluster ID"
  value       = module.enhanced_container_infrastructure.cluster_id
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.enhanced_container_infrastructure.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.enhanced_container_infrastructure.cluster_security_group_id
}

output "cluster_iam_role_name" {
  description = "IAM role name associated with EKS cluster"
  value       = module.enhanced_container_infrastructure.cluster_iam_role_name
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN associated with EKS cluster"
  value       = module.enhanced_container_infrastructure.cluster_iam_role_arn
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.enhanced_container_infrastructure.cluster_certificate_authority_data
}

output "eks_managed_node_groups" {
  description = "Map of EKS managed node groups"
  value       = module.enhanced_container_infrastructure.eks_managed_node_groups
}

output "fargate_profiles" {
  description = "Map of EKS Fargate profiles"
  value       = module.enhanced_container_infrastructure.fargate_profiles
}

output "ecr_repository_urls" {
  description = "Map of ECR repository URLs"
  value       = module.enhanced_container_infrastructure.ecr_repository_urls
}

output "ecr_repository_arns" {
  description = "Map of ECR repository ARNs"
  value       = module.enhanced_container_infrastructure.ecr_repository_arns
}

output "custom_security_group_ids" {
  description = "Map of custom security group IDs"
  value       = module.enhanced_container_infrastructure.custom_security_group_ids
}

output "kubeconfig" {
  description = "Kubeconfig file content"
  value       = module.enhanced_container_infrastructure.kubeconfig
  sensitive   = true
}

output "kubeconfig_filename" {
  description = "Kubeconfig filename"
  value       = module.enhanced_container_infrastructure.kubeconfig_filename
}

output "cloudwatch_container_insights_status" {
  description = "Status of CloudWatch Container Insights"
  value       = module.enhanced_container_infrastructure.cloudwatch_container_insights_status
}

output "aws_load_balancer_controller_status" {
  description = "Status of AWS Load Balancer Controller"
  value       = module.enhanced_container_infrastructure.aws_load_balancer_controller_status
}

output "metrics_server_status" {
  description = "Status of Metrics Server"
  value       = module.enhanced_container_infrastructure.metrics_server_status
}

output "cluster_autoscaler_status" {
  description = "Status of Cluster Autoscaler"
  value       = module.enhanced_container_infrastructure.cluster_autoscaler_status
}

output "ecr_vulnerability_scanning_status" {
  description = "Status of ECR vulnerability scanning"
  value       = module.enhanced_container_infrastructure.ecr_vulnerability_scanning_status
}

output "ecr_pull_through_cache_rules" {
  description = "Map of ECR pull through cache rules"
  value       = module.enhanced_container_infrastructure.ecr_pull_through_cache_rules
}

output "region" {
  description = "AWS region"
  value       = module.enhanced_container_infrastructure.region
}

output "account_id" {
  description = "AWS account ID"
  value       = module.enhanced_container_infrastructure.account_id
}

output "tags" {
  description = "Common tags applied to all resources"
  value       = module.enhanced_container_infrastructure.tags
} 