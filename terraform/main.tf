terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}


# ============================================================================
# VPC & NETWORKING
# ============================================================================

resource "aws_vpc" "ids_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "IDS-VPC"
  }
}

resource "aws_internet_gateway" "ids_igw" {
  vpc_id = aws_vpc.ids_vpc.id

  tags = {
    Name = "IDS-IGW"
  }
}


# ============================================================================
# ATTACKER / DETECTION SUBNET
# ============================================================================

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.ids_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "IDS-Public-Subnet"
  }
}


# ============================================================================
# TARGET SUBNET
# ============================================================================

resource "aws_subnet" "target_subnet" {
  vpc_id                  = aws_vpc.ids_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "IDS-Target-Subnet"
  }
}


# ============================================================================
# ROUTING
# ============================================================================

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.ids_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ids_igw.id
  }

  tags = {
    Name = "IDS-Public-RT"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "target_assoc" {
  subnet_id      = aws_subnet.target_subnet.id
  route_table_id = aws_route_table.public_rt.id
}


# ============================================================================
# TARGET SUBNET NETWORK ACL
# ============================================================================

resource "aws_network_acl" "target_nacl" {
  vpc_id = aws_vpc.ids_vpc.id

  tags = {
    Name = "IDS-Target-NACL"
  }
}

resource "aws_network_acl_association" "target_nacl_assoc" {
  subnet_id      = aws_subnet.target_subnet.id
  network_acl_id = aws_network_acl.target_nacl.id
}

# Baseline inbound ALLOW.
# Lambda-created DENY rules use lower rule numbers (100-499),
# so they are evaluated before this rule.

resource "aws_network_acl_rule" "target_nacl_ingress_allow" {
  network_acl_id = aws_network_acl.target_nacl.id
  rule_number    = 1000
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# Baseline outbound ALLOW.

resource "aws_network_acl_rule" "target_nacl_egress_allow" {
  network_acl_id = aws_network_acl.target_nacl.id
  rule_number    = 1000
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

output "target_nacl_id" {
  description = "Dedicated NACL used for deny-based enforcement on the target subnet"
  value       = aws_network_acl.target_nacl.id
}


# ============================================================================
# SECURITY GROUPS
# ============================================================================

# ----------------------------------------------------------------------------
# TARGET SECURITY GROUP
#
# IMPORTANT:
# Attackers are in 10.0.1.0/24.
# The target is in 10.0.2.0/24.
#
# We allow the attacker subnet here so that NORMAL traffic works before an
# attack. The NACL is then responsible for dynamically blocking attackers.
# ----------------------------------------------------------------------------

resource "aws_security_group" "target_sg" {
  name        = "target-sg"
  description = "Security group for the Target server"
  vpc_id      = aws_vpc.ids_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.target_sg_cidr, "10.0.1.0/24"]
  }

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.target_sg_cidr, "10.0.1.0/24"]
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.target_sg_cidr, "10.0.1.0/24"]
  }

  # ICMP / Ping
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.target_sg_cidr, "10.0.1.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Target-SG"
  }
}


# ----------------------------------------------------------------------------
# ATTACKER SECURITY GROUP
# ----------------------------------------------------------------------------

resource "aws_security_group" "attacker_sg" {
  name        = "attacker-sg"
  description = "Security group for the Attacker server"
  vpc_id      = aws_vpc.ids_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.attacker_sg_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Attacker-SG"
  }
}


# ----------------------------------------------------------------------------
# DETECTION SECURITY GROUP
# ----------------------------------------------------------------------------

resource "aws_security_group" "detection_sg" {
  name        = "detection-sg"
  description = "Security group for the Detection server"
  vpc_id      = aws_vpc.ids_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.target_sg_cidr]
  }

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [var.target_sg_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Detection-SG"
  }
}


# ============================================================================
# IAM ROLES
# ============================================================================

# ----------------------------------------------------------------------------
# VPC Flow Logs Role
# ----------------------------------------------------------------------------

resource "aws_iam_role" "flow_logs_role" {
  name = "ids-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"

      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "IDS-FlowLogs-Role"
  }
}


resource "aws_iam_role_policy" "flow_logs_policy" {
  name = "ids-flow-logs-policy"
  role = aws_iam_role.flow_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"

      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]

      Resource = "*"
    }]
  })
}


# ----------------------------------------------------------------------------
# Lambda Detection / Automated Response Role
# ----------------------------------------------------------------------------

resource "aws_iam_role" "detection_engine_role" {
  name = "ids-detection-engine-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"

      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "IDS-Detection-Role"
  }
}


resource "aws_iam_role_policy" "detection_engine_policy" {
  name = "ids-detection-engine-policy"
  role = aws_iam_role.detection_engine_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # CloudWatch Logs permissions

      {
        Effect = "Allow"

        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:FilterLogEvents",
          "logs:GetLogEvents"
        ]

        Resource = "*"
      },

      # Security Group + Network ACL permissions

      {
        Effect = "Allow"

        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",

          "ec2:CreateNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:DescribeNetworkAcls",
          "ec2:ReplaceNetworkAclEntry"
        ]

        Resource = "*"
      }
    ]
  })
}


# ----------------------------------------------------------------------------
# Detection EC2 Role
# ----------------------------------------------------------------------------

resource "aws_iam_role" "detection_ec2_role" {
  name = "ids-detection-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"

      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "IDS-Detection-EC2-Role"
  }
}


resource "aws_iam_role_policy" "detection_ec2_policy" {
  name = "ids-detection-ec2-policy"
  role = aws_iam_role.detection_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # CloudWatch permissions

      {
        Effect = "Allow"

        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:FilterLogEvents",
          "logs:GetLogEvents"
        ]

        Resource = "*"
      },

      # Existing Security Group permissions

      {
        Effect = "Allow"

        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules"
        ]

        Resource = "*"
      },

      # Allow Detection Server to invoke Lambda

      {
        Effect = "Allow"

        Action = [
          "lambda:InvokeFunction"
        ]

        Resource = aws_lambda_function.add_block.arn
      }
    ]
  })
}


resource "aws_iam_instance_profile" "detection_profile" {
  name = "ids-detection-instance-profile"
  role = aws_iam_role.detection_ec2_role.name
}


# ============================================================================
# CLOUDWATCH LOG GROUP FOR VPC FLOW LOGS
# ============================================================================

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/ids-flow-logs"
  retention_in_days = 7

  tags = {
    Name = "IDS-FlowLogs"
  }
}


# ============================================================================
# VPC FLOW LOGS
# ============================================================================

resource "aws_flow_log" "ids_flow_log" {
  vpc_id                   = aws_vpc.ids_vpc.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs_role.arn
  max_aggregation_interval = 60

  tags = {
    Name = "IDS-FlowLog"
  }
}


# ============================================================================
# EC2 AMI
# ============================================================================

data "aws_ami" "ubuntu_22_04" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}


# ============================================================================
# EC2 INSTANCES
# ============================================================================

# ----------------------------------------------------------------------------
# Target Server
# ----------------------------------------------------------------------------

resource "aws_instance" "target" {
  ami                    = data.aws_ami.ubuntu_22_04.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.target_subnet.id
  vpc_security_group_ids = [aws_security_group.target_sg.id]
  key_name               = var.key_name

  root_block_device {
    volume_size           = 8
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "Target-Server"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}


# ----------------------------------------------------------------------------
# Attacker Server
# ----------------------------------------------------------------------------

resource "aws_instance" "attacker" {
  ami                    = data.aws_ami.ubuntu_22_04.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.attacker_sg.id]
  key_name               = var.key_name

  root_block_device {
    volume_size           = 8
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "Attacker-Server"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}


# ----------------------------------------------------------------------------
# Attacker Server 2
# ----------------------------------------------------------------------------

resource "aws_instance" "attacker2" {
  ami                    = data.aws_ami.ubuntu_22_04.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.attacker_sg.id]
  key_name               = var.key_name

  root_block_device {
    volume_size           = 8
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "Attacker-Server-2"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}


# ----------------------------------------------------------------------------
# Detection Server
# ----------------------------------------------------------------------------

resource "aws_instance" "detection" {
  ami                    = data.aws_ami.ubuntu_22_04.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.detection_sg.id]
  key_name               = var.key_name
  iam_instance_profile   = aws_iam_instance_profile.detection_profile.name

  root_block_device {
    volume_size           = 8
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "Detection-Server"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}
