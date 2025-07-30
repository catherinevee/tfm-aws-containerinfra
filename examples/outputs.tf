# Example outputs for the EC2 module

# Basic EC2 Instance Outputs
output "basic_ec2_instance_id" {
  description = "ID of the basic EC2 instance"
  value       = module.basic_ec2.instance_ids[0]
}

output "basic_ec2_public_ip" {
  description = "Public IP of the basic EC2 instance"
  value       = module.basic_ec2.instance_public_ips[0]
}

output "basic_ec2_private_ip" {
  description = "Private IP of the basic EC2 instance"
  value       = module.basic_ec2.instance_private_ips[0]
}

output "basic_ec2_security_group_id" {
  description = "ID of the security group for the basic EC2 instance"
  value       = module.basic_ec2.security_group_id
}

# EC2 Instance with Key Pair Outputs
output "key_ec2_instance_id" {
  description = "ID of the EC2 instance with key pair"
  value       = module.ec2_with_key.instance_ids[0]
}

output "key_ec2_key_pair_name" {
  description = "Name of the key pair for the EC2 instance"
  value       = module.ec2_with_key.key_pair_name
}

output "key_ec2_public_ip" {
  description = "Public IP of the EC2 instance with key pair"
  value       = module.ec2_with_key.instance_public_ips[0]
}

# EC2 Instance with IAM Role Outputs
output "iam_ec2_instance_id" {
  description = "ID of the EC2 instance with IAM role"
  value       = module.ec2_with_iam.instance_ids[0]
}

output "iam_ec2_role_arn" {
  description = "ARN of the IAM role for the EC2 instance"
  value       = module.ec2_with_iam.iam_role_arn
}

output "iam_ec2_instance_profile_name" {
  description = "Name of the IAM instance profile for the EC2 instance"
  value       = module.ec2_with_iam.iam_instance_profile_name
}

output "iam_ec2_private_ip" {
  description = "Private IP of the EC2 instance with IAM role"
  value       = module.ec2_with_iam.instance_private_ips[0]
}

# Auto Scaling Group Outputs
output "asg_id" {
  description = "ID of the Auto Scaling Group"
  value       = module.ec2_asg.autoscaling_group_id
}

output "asg_name" {
  description = "Name of the Auto Scaling Group"
  value       = module.ec2_asg.autoscaling_group_name
}

output "asg_desired_capacity" {
  description = "Desired capacity of the Auto Scaling Group"
  value       = module.ec2_asg.autoscaling_group_desired_capacity
}

output "asg_max_size" {
  description = "Maximum size of the Auto Scaling Group"
  value       = module.ec2_asg.autoscaling_group_max_size
}

output "asg_min_size" {
  description = "Minimum size of the Auto Scaling Group"
  value       = module.ec2_asg.autoscaling_group_min_size
}

output "asg_launch_template_id" {
  description = "ID of the launch template used by the Auto Scaling Group"
  value       = module.ec2_asg.launch_template_id
}

output "asg_launch_template_name" {
  description = "Name of the launch template used by the Auto Scaling Group"
  value       = module.ec2_asg.launch_template_name
}

output "asg_policy_ids" {
  description = "IDs of the Auto Scaling policies"
  value       = module.ec2_asg.autoscaling_policy_ids
}

output "asg_policy_names" {
  description = "Names of the Auto Scaling policies"
  value       = module.ec2_asg.autoscaling_policy_names
}

output "asg_cloudwatch_alarm_ids" {
  description = "IDs of the CloudWatch alarms for the Auto Scaling Group"
  value       = module.ec2_asg.cloudwatch_alarm_ids
}

output "asg_cloudwatch_alarm_names" {
  description = "Names of the CloudWatch alarms for the Auto Scaling Group"
  value       = module.ec2_asg.cloudwatch_alarm_names
}

# Multiple EC2 Instances Outputs
output "multi_ec2_instance_ids" {
  description = "IDs of the multiple EC2 instances"
  value       = module.multiple_ec2.instance_ids
}

output "multi_ec2_public_ips" {
  description = "Public IPs of the multiple EC2 instances"
  value       = module.multiple_ec2.instance_public_ips
}

output "multi_ec2_private_ips" {
  description = "Private IPs of the multiple EC2 instances"
  value       = module.multiple_ec2.instance_private_ips
}

output "multi_ec2_security_group_id" {
  description = "ID of the security group for the multiple EC2 instances"
  value       = module.multiple_ec2.security_group_id
}

# AMI Outputs
output "amazon_linux_2_ami_id" {
  description = "Amazon Linux 2 AMI ID used in examples"
  value       = module.basic_ec2.amazon_linux_2_ami_id
}

output "ubuntu_ami_id" {
  description = "Ubuntu AMI ID used in examples"
  value       = module.ec2_with_key.ubuntu_ami_id
}

# Summary Outputs
output "all_instance_ids" {
  description = "All EC2 instance IDs from all examples"
  value = concat(
    module.basic_ec2.instance_ids,
    module.ec2_with_key.instance_ids,
    module.ec2_with_iam.instance_ids,
    module.multiple_ec2.instance_ids
  )
}

output "all_public_ips" {
  description = "All public IP addresses from all examples"
  value = concat(
    module.basic_ec2.instance_public_ips,
    module.ec2_with_key.instance_public_ips,
    module.ec2_with_iam.instance_public_ips,
    module.multiple_ec2.instance_public_ips
  )
}

output "all_security_group_ids" {
  description = "All security group IDs from all examples"
  value = compact([
    module.basic_ec2.security_group_id,
    module.ec2_with_iam.security_group_id,
    module.ec2_asg.security_group_id,
    module.multiple_ec2.security_group_id
  ])
}

output "all_key_pair_names" {
  description = "All key pair names from all examples"
  value = compact([
    module.ec2_with_key.key_pair_name
  ])
}

output "all_iam_role_arns" {
  description = "All IAM role ARNs from all examples"
  value = compact([
    module.ec2_with_iam.iam_role_arn
  ])
}

output "all_launch_template_ids" {
  description = "All launch template IDs from all examples"
  value = compact([
    module.ec2_asg.launch_template_id
  ])
}

output "all_autoscaling_group_ids" {
  description = "All Auto Scaling Group IDs from all examples"
  value = compact([
    module.ec2_asg.autoscaling_group_id
  ])
} 