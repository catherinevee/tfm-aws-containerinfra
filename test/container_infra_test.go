package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestContainerInfraModule(t *testing.T) {
	t.Parallel()

	// Generate a random name to prevent a naming conflict
	uniqueID := strings.ToLower(random.UniqueId())
	name := fmt.Sprintf("container-test-%s", uniqueID)
	awsRegion := "us-west-2"

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/basic",
		Vars: map[string]interface{}{
			"name":        name,
			"environment": "test",
			"vpc_config": map[string]interface{}{
				"cidr_block":         "10.0.0.0/16",
				"enable_nat_gateway": true,
				"single_nat_gateway": true,
				"enable_flow_log":    true,
			},
			"subnet_config": map[string]interface{}{
				"azs":             []string{"us-west-2a", "us-west-2b"},
				"private_subnets": []string{"10.0.1.0/24", "10.0.2.0/24"},
				"public_subnets":  []string{"10.0.101.0/24", "10.0.102.0/24"},
			},
			"eks_config": map[string]interface{}{
				"cluster_version": "1.28",
				"enable_irsa":     true,
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	})

	// Clean up everything at the end of the test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the module
	terraform.InitAndApply(t, terraformOptions)

	// Test VPC Configuration
	vpcID := terraform.Output(t, terraformOptions, "vpc_id")
	vpc := aws.GetVpcById(t, vpcID, awsRegion)
	assert.Equal(t, "10.0.0.0/16", *vpc.CidrBlock)

	// Test EKS Cluster
	clusterName := terraform.Output(t, terraformOptions, "cluster_name")
	cluster := aws.GetEksCluster(t, awsRegion, clusterName)
	assert.Equal(t, "ACTIVE", *cluster.Status)

	// Test ECR Repositories
	ecrRepos := terraform.OutputList(t, terraformOptions, "ecr_repository_urls")
	for _, repoUrl := range ecrRepos {
		assert.Contains(t, repoUrl, "dkr.ecr.us-west-2.amazonaws.com")
	}

	// Test Security Groups
	sgID := terraform.Output(t, terraformOptions, "cluster_security_group_id")
	securityGroup := aws.GetSecurityGroupById(t, sgID, awsRegion)
	assert.NotNil(t, securityGroup)

	// Test CloudWatch Log Groups
	logGroupName := terraform.Output(t, terraformOptions, "cloudwatch_log_group_name")
	assert.NotEmpty(t, logGroupName)

	// Test IAM Roles
	clusterRoleArn := terraform.Output(t, terraformOptions, "cluster_iam_role_arn")
	assert.Contains(t, clusterRoleArn, "arn:aws:iam::")
	assert.Contains(t, clusterRoleArn, ":role/")

	// Test Tags
	tags := aws.GetTagsForVpc(t, vpcID, awsRegion)
	assert.Equal(t, "test", tags["Environment"])
	assert.Equal(t, name, tags["Name"])
	assert.Equal(t, "terraform", tags["ManagedBy"])
}

func TestContainerInfraSecurity(t *testing.T) {
	t.Parallel()

	uniqueID := strings.ToLower(random.UniqueId())
	name := fmt.Sprintf("security-test-%s", uniqueID)
	awsRegion := "us-west-2"

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		Vars: map[string]interface{}{
			"name":        name,
			"environment": "test",
			"vpc_config": map[string]interface{}{
				"cidr_block":         "10.0.0.0/16",
				"enable_nat_gateway": true,
				"enable_flow_log":    true,
			},
			"eks_config": map[string]interface{}{
				"cluster_version":           "1.28",
				"enable_irsa":               true,
				"cluster_encryption_config": []map[string]interface{}{{"provider_key_arn": ""}},
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	// Test KMS Encryption
	kmsKeyId := terraform.Output(t, terraformOptions, "cluster_encryption_key_arn")
	assert.NotEmpty(t, kmsKeyId)

	// Test Security Groups
	sgId := terraform.Output(t, terraformOptions, "cluster_security_group_id")
	sg := aws.GetSecurityGroupById(t, sgId, awsRegion)

	// Verify no 0.0.0.0/0 ingress rules
	for _, rule := range sg.IpPermissions {
		for _, ipRange := range rule.IpRanges {
			assert.NotEqual(t, "0.0.0.0/0", *ipRange.CidrIp, "Found overly permissive ingress rule")
		}
	}

	// Test IAM Roles
	nodeRoleArn := terraform.Output(t, terraformOptions, "node_role_arn")
	assert.Contains(t, nodeRoleArn, "arn:aws:iam::")

	// Additional security checks can be added here
}
