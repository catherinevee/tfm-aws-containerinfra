# ==============================================================================
# Basic Example Outputs
# ==============================================================================

output "vpc_id" {
  description = "VPC ID"
  value       = module.container_infrastructure.vpc_id
}

output "cluster_id" {
  description = "EKS Cluster ID"
  value       = module.container_infrastructure.cluster_id
}

output "cluster_endpoint" {
  description = "EKS Cluster endpoint"
  value       = module.container_infrastructure.cluster_endpoint
}

output "ecr_repository_urls" {
  description = "ECR Repository URLs"
  value       = module.container_infrastructure.ecr_repository_urls
}

output "private_subnets" {
  description = "Private subnet IDs"
  value       = module.container_infrastructure.private_subnets
}

output "public_subnets" {
  description = "Public subnet IDs"
  value       = module.container_infrastructure.public_subnets
}

output "eks_cluster_security_group_id" {
  description = "EKS Cluster Security Group ID"
  value       = module.container_infrastructure.eks_cluster_security_group_id
}

output "eks_nodes_security_group_id" {
  description = "EKS Nodes Security Group ID"
  value       = module.container_infrastructure.eks_nodes_security_group_id
}

output "custom_security_group_ids" {
  description = "Custom Security Group IDs"
  value       = module.container_infrastructure.custom_security_group_ids
} 