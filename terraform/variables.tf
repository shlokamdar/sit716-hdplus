variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-south-1"
}

variable "my_public_ip" {
  description = "Your public IP address for SSH access (find at https://checkip.amazonaws.com/)"
  type        = string
}

variable "key_name" {
  description = "Name of an existing EC2 Key Pair in AWS for SSH access"
  type        = string
}

variable "target_sg_cidr" {
  description = "CIDR block for your IP to access Target (e.g., 203.0.113.5/32)"
  type        = string
}

variable "attacker_sg_cidr" {
  description = "CIDR block for your IP to access Attacker (e.g., 203.0.113.5/32)"
  type        = string
}