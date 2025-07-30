# ==============================================================================
# Test Outputs for Container Infrastructure Module
# ==============================================================================

# VPC Outputs
output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.container_infrastructure_test.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.container_infrastructure_test.vpc_cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.container_infrastructure_test.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.container_infrastructure_test.public_subnets
}

# EKS Outputs
output "cluster_id" {
  description = "EKS cluster ID"
  value       = module.container_infrastructure_test.cluster_id
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.container_infrastructure_test.cluster_endpoint
}

output "cluster_oidc_issuer_url" {
  description = "EKS cluster OIDC issuer URL"
  value       = module.container_infrastructure_test.cluster_oidc_issuer_url
}

output "cluster_certificate_authority_data" {
  description = "EKS cluster certificate authority data"
  value       = module.container_infrastructure_test.cluster_certificate_authority_data
}

output "cluster_iam_role_arn" {
  description = "EKS cluster IAM role ARN"
  value       = module.container_infrastructure_test.cluster_iam_role_arn
}

# ECR Outputs
output "ecr_repository_urls" {
  description = "ECR repository URLs"
  value       = module.container_infrastructure_test.ecr_repository_urls
}

output "ecr_repository_arns" {
  description = "ECR repository ARNs"
  value       = module.container_infrastructure_test.ecr_repository_arns
}

output "ecr_registry_url" {
  description = "ECR registry URL"
  value       = module.container_infrastructure_test.ecr_registry_url
}

output "ecr_vulnerability_scanning_status" {
  description = "Status of ECR vulnerability scanning"
  value       = module.container_infrastructure_test.ecr_vulnerability_scanning_status
}

output "ecr_pull_through_cache_rules" {
  description = "ECR pull-through cache rules"
  value       = module.container_infrastructure_test.ecr_pull_through_cache_rules
}

# Security Groups Outputs
output "eks_cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.container_infrastructure_test.eks_cluster_security_group_id
}

output "eks_nodes_security_group_id" {
  description = "Security group ID attached to the EKS nodes"
  value       = module.container_infrastructure_test.eks_nodes_security_group_id
}

output "custom_security_group_ids" {
  description = "Map of custom security group IDs"
  value       = module.container_infrastructure_test.custom_security_group_ids
}

# Monitoring Outputs
output "cloudwatch_container_insights_status" {
  description = "Status of CloudWatch Container Insights"
  value       = module.container_infrastructure_test.cloudwatch_container_insights_status
}

output "aws_load_balancer_controller_status" {
  description = "Status of AWS Load Balancer Controller"
  value       = module.container_infrastructure_test.aws_load_balancer_controller_status
}

output "metrics_server_status" {
  description = "Status of Metrics Server"
  value       = module.container_infrastructure_test.metrics_server_status
}

output "cluster_autoscaler_status" {
  description = "Status of Cluster Autoscaler"
  value       = module.container_infrastructure_test.cluster_autoscaler_status
}

output "prometheus_status" {
  description = "Status of Prometheus monitoring stack"
  value       = module.container_infrastructure_test.prometheus_status
}

output "kubernetes_dashboard_status" {
  description = "Status of Kubernetes Dashboard"
  value       = module.container_infrastructure_test.kubernetes_dashboard_status
}

output "jaeger_status" {
  description = "Status of Jaeger distributed tracing"
  value       = module.container_infrastructure_test.jaeger_status
}

# Network Policies Outputs
output "calico_status" {
  description = "Status of Calico network policies"
  value       = module.container_infrastructure_test.calico_status
}

output "cilium_status" {
  description = "Status of Cilium network policies"
  value       = module.container_infrastructure_test.cilium_status
}

# Backup Outputs
output "velero_status" {
  description = "Status of Velero backup solution"
  value       = module.container_infrastructure_test.velero_status
}

# General Outputs
output "tags" {
  description = "Common tags applied to all resources"
  value       = module.container_infrastructure_test.tags
}

output "region" {
  description = "AWS region"
  value       = module.container_infrastructure_test.region
}

output "account_id" {
  description = "AWS account ID"
  value       = module.container_infrastructure_test.account_id
}

# Kubeconfig Outputs
output "kubeconfig" {
  description = "Kubeconfig for the EKS cluster"
  value       = module.container_infrastructure_test.kubeconfig
  sensitive   = true
}

output "kubeconfig_filename" {
  description = "Filename for the kubeconfig"
  value       = module.container_infrastructure_test.kubeconfig_filename
} 