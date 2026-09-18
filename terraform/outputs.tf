output "target_public_ip" {
  description = "Public IP of the Target server"
  value       = aws_instance.target.public_ip
}

output "attacker_public_ip" {
  description = "Public IP of the Attacker server"
  value       = aws_instance.attacker.public_ip
}

output "attacker2_public_ip" {
  description = "Public IP of Attacker server 2"
  value       = aws_instance.attacker2.public_ip
}


output "detection_public_ip" {
  description = "Public IP of the Detection server"
  value       = aws_instance.detection.public_ip
}

output "target_private_ip" {
  description = "Private IP of the Target server"
  value       = aws_instance.target.private_ip
}

output "attacker_private_ip" {
  description = "Private IP of the Attacker server"
  value       = aws_instance.attacker.private_ip
}

output "attacker2_private_ip" {
  description = "Private IP of Attacker server 2"
  value       = aws_instance.attacker2.private_ip
}


output "detection_private_ip" {
  description = "Private IP of the Detection server"
  value       = aws_instance.detection.private_ip
}

output "vpc_id" {
  description = "ID of the created VPC"
  value       = aws_vpc.ids_vpc.id
}

output "flow_log_group_name" {
  description = "CloudWatch Log Group for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.vpc_flow_logs.name
}

output "ssh_target_command" {
  description = "SSH command for Target"
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${aws_instance.target.public_ip}"
}

output "ssh_attacker_command" {
  description = "SSH command for Attacker"
  value       = "ssh -i ${var.key_name}.pem ubuntu@${aws_instance.attacker.public_ip}"
}

output "ssh_attacker2_command" {
  description = "SSH command for Attacker server 2"
  value       = "ssh -i ${var.key_name}.pem ubuntu@${aws_instance.attacker2.public_ip}"
}


output "ssh_detection_command" {
  description = "SSH command for Detection server"
  value       = "ssh -i ${var.key_name}.pem ubuntu@${aws_instance.detection.public_ip}"
}
