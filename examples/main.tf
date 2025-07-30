# Example usage of the custom EC2 module

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}

# Example 1: Basic EC2 Instance
module "basic_ec2" {
  source = "../"

  instance_name = "basic-instance"
  instance_type = "t3.micro"
  subnet_id     = "subnet-12345678" # Replace with your subnet ID

  # Use latest Amazon Linux 2 AMI
  use_latest_ami = true
  ami_type       = "amazon_linux_2"

  # Create security group with SSH access
  create_security_group = true
  vpc_id                = "vpc-12345678" # Replace with your VPC ID

  security_group_ingress_rules = [
    {
      description     = "SSH access"
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      self            = false
    },
    {
      description     = "HTTP access"
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      self            = false
    }
  ]

  # Associate public IP
  associate_public_ip_address = true

  # Root block device configuration
  root_block_device = [
    {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 20
      volume_type           = "gp3"
    }
  ]

  tags = {
    Environment = "example"
    Project     = "terraform-ec2-module"
    Owner       = "devops"
  }
}

# Example 2: EC2 Instance with Key Pair
module "ec2_with_key" {
  source = "../"

  instance_name = "key-instance"
  instance_type = "t3.small"
  subnet_id     = "subnet-12345678" # Replace with your subnet ID

  # Create key pair
  create_key_pair = true
  public_key      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." # Replace with your public key

  # Use existing security group
  create_security_group = false
  security_group_ids    = ["sg-12345678"] # Replace with your security group ID

  # Use Ubuntu AMI
  use_latest_ami = true
  ami_type       = "ubuntu"

  # User data script
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Hello from Terraform EC2 Module!</h1>" > /var/www/html/index.html
              EOF

  tags = {
    Environment = "example"
    Project     = "terraform-ec2-module"
    Owner       = "devops"
  }
}

# Example 3: EC2 Instance with IAM Role
module "ec2_with_iam" {
  source = "../"

  instance_name = "iam-instance"
  instance_type = "t3.medium"
  subnet_id     = "subnet-12345678" # Replace with your subnet ID

  # Create IAM role
  create_iam_role = true
  iam_policy_statements = [
    {
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ]
      Resource = [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    },
    {
      Effect = "Allow"
      Action = [
        "ec2:DescribeInstances",
        "ec2:DescribeTags"
      ]
      Resource = "*"
    }
  ]

  # Use custom AMI
  custom_ami_id    = "ami-12345678" # Replace with your custom AMI ID
  custom_ami_owner = "self"

  # Create security group
  create_security_group = true
  vpc_id                = "vpc-12345678" # Replace with your VPC ID

  security_group_ingress_rules = [
    {
      description     = "SSH access"
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      cidr_blocks     = ["10.0.0.0/8"]
      security_groups = []
      self            = false
    }
  ]

  tags = {
    Environment = "example"
    Project     = "terraform-ec2-module"
    Owner       = "devops"
  }
}

# Example 4: EC2 Instance with Launch Template and Auto Scaling Group
module "ec2_asg" {
  source = "../"

  instance_name = "asg-instance"
  instance_type = "t3.micro"
  subnet_id     = "subnet-12345678" # Replace with your subnet ID

  # Use launch template
  use_launch_template = true

  # Create Auto Scaling Group
  create_autoscaling_group = true
  asg_desired_capacity     = 2
  asg_max_size             = 5
  asg_min_size             = 1
  asg_subnet_ids           = ["subnet-12345678", "subnet-87654321"] # Replace with your subnet IDs

  # Auto Scaling Group tags
  asg_tags = [
    {
      key                 = "Name"
      value               = "asg-instance"
      propagate_at_launch = true
    },
    {
      key                 = "Environment"
      value               = "example"
      propagate_at_launch = true
    }
  ]

  # Auto Scaling policies
  asg_policies = {
    scale_up = {
      name                   = "scale-up"
      adjustment_type        = "ChangeInCapacity"
      scaling_adjustment     = 1
      cooldown               = 300
      metric_aggregation_type = "Average"
    },
    scale_down = {
      name                   = "scale-down"
      adjustment_type        = "ChangeInCapacity"
      scaling_adjustment     = -1
      cooldown               = 300
      metric_aggregation_type = "Average"
    }
  }

  # CloudWatch alarms
  cloudwatch_alarms = {
    high_cpu = {
      alarm_name          = "high-cpu-utilization"
      comparison_operator = "GreaterThanThreshold"
      evaluation_periods  = 2
      metric_name         = "CPUUtilization"
      namespace           = "AWS/EC2"
      period              = 120
      statistic           = "Average"
      threshold           = 80
      alarm_description   = "Scale up if CPU > 80% for 4 minutes"
      dimensions = [
        {
          name  = "AutoScalingGroupName"
          value = "asg-instance"
        }
      ]
    },
    low_cpu = {
      alarm_name          = "low-cpu-utilization"
      comparison_operator = "LessThanThreshold"
      evaluation_periods  = 2
      metric_name         = "CPUUtilization"
      namespace           = "AWS/EC2"
      period              = 120
      statistic           = "Average"
      threshold           = 20
      alarm_description   = "Scale down if CPU < 20% for 4 minutes"
      dimensions = [
        {
          name  = "AutoScalingGroupName"
          value = "asg-instance"
        }
      ]
    }
  }

  # Create security group
  create_security_group = true
  vpc_id                = "vpc-12345678" # Replace with your VPC ID

  security_group_ingress_rules = [
    {
      description     = "SSH access"
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      cidr_blocks     = ["10.0.0.0/8"]
      security_groups = []
      self            = false
    },
    {
      description     = "HTTP access"
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      self            = false
    }
  ]

  # Block device mappings for launch template
  block_device_mappings = [
    {
      device_name = "/dev/xvda"
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 30
        volume_type           = "gp3"
        throughput            = 125
      }
    }
  ]

  # User data script
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Hello from Auto Scaling Group!</h1>" > /var/www/html/index.html
              echo "<p>Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id)</p>" >> /var/www/html/index.html
              EOF

  tags = {
    Environment = "example"
    Project     = "terraform-ec2-module"
    Owner       = "devops"
  }
}

# Example 5: Multiple EC2 Instances
module "multiple_ec2" {
  source = "../"

  instance_name = "multi-instance"
  instance_count = 3
  instance_type = "t3.micro"
  subnet_id     = "subnet-12345678" # Replace with your subnet ID

  # Use latest Amazon Linux 2 AMI
  use_latest_ami = true
  ami_type       = "amazon_linux_2"

  # Create security group
  create_security_group = true
  vpc_id                = "vpc-12345678" # Replace with your VPC ID

  security_group_ingress_rules = [
    {
      description     = "SSH access"
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      cidr_blocks     = ["10.0.0.0/8"]
      security_groups = []
      self            = false
    }
  ]

  # Root block device configuration
  root_block_device = [
    {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 25
      volume_type           = "gp3"
    }
  ]

  # User data script
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Hello from Multi-Instance Setup!</h1>" > /var/www/html/index.html
              echo "<p>Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id)</p>" >> /var/www/html/index.html
              EOF

  tags = {
    Environment = "example"
    Project     = "terraform-ec2-module"
    Owner       = "devops"
  }
} 