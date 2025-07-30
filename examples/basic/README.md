# Basic Container Infrastructure Example

This example demonstrates a basic container infrastructure setup using the AWS Container Infrastructure Terraform module.

## What's Included

- **VPC**: Single NAT gateway for cost optimization
- **EKS Cluster**: Single node group with t3.medium instances
- **ECR Repository**: Single repository with lifecycle policies
- **Security Groups**: Basic security group for application pods
- **Monitoring**: CloudWatch Container Insights, Metrics Server, and Load Balancer Controller

## Usage

1. **Initialize Terraform**:
   ```bash
   terraform init
   ```

2. **Review the plan**:
   ```bash
   terraform plan
   ```

3. **Apply the configuration**:
   ```bash
   terraform apply
   ```

4. **Configure kubectl**:
   ```bash
   aws eks update-kubeconfig --region us-west-2 --name my-app-eks-cluster
   ```

5. **Verify the cluster**:
   ```bash
   kubectl get nodes
   kubectl get pods --all-namespaces
   ```

## Configuration Details

### VPC
- CIDR: `10.0.0.0/16`
- 2 Availability Zones
- Public and private subnets
- Single NAT gateway for cost optimization

### EKS Cluster
- Kubernetes version: 1.28 (default)
- Node group: 2-4 t3.medium instances
- On-demand instances for stability

### ECR Repository
- Repository name: `my-app`
- Image scanning enabled
- Lifecycle policy: Keep 30 images, expire after 90 days

### Security Groups
- Application security group with HTTP/HTTPS access from VPC

## Estimated Costs

- **EKS**: ~$73/month (2 t3.medium instances)
- **ECR**: ~$0.10 per GB-month
- **NAT Gateway**: ~$45/month
- **VPC**: Minimal cost

**Total**: ~$120/month

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

## Next Steps

After deploying this basic setup, you can:

1. Deploy applications to the EKS cluster
2. Push container images to the ECR repository
3. Configure ingress controllers
4. Set up monitoring and alerting
5. Implement CI/CD pipelines

## Troubleshooting

### Common Issues

1. **NAT Gateway costs**: Consider using single NAT gateway for dev environments
2. **Node group scaling**: Adjust min/max sizes based on workload requirements
3. **ECR access**: Ensure EKS nodes have proper IAM permissions to pull from ECR

### Useful Commands

```bash
# Check cluster status
kubectl cluster-info

# List all resources
kubectl get all --all-namespaces

# Check node group status
aws eks describe-nodegroup --cluster-name my-app-eks-cluster --nodegroup-name general

# View ECR repository
aws ecr describe-repositories --repository-names my-app
``` 