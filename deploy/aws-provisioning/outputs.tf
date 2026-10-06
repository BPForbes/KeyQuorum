output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.relay.id
}

output "instance_public_ip" {
  description = "Public IP address of the relay instance"
  value       = aws_eip.relay.public_ip
}

output "instance_type" {
  description = "EC2 instance type"
  value       = aws_instance.relay.instance_type
}

output "security_group_id" {
  description = "Security group ID for the relay"
  value       = aws_security_group.relay.id
}

output "kms_key_id" {
  description = "KMS key ID for EBS encryption"
  value       = aws_kms_key.ebs.id
}

output "kms_key_arn" {
  description = "KMS key ARN for EBS encryption"
  value       = aws_kms_key.ebs.arn
}

output "data_volume_id" {
  description = "EBS volume ID for relay database"
  value       = aws_ebs_volume.relay_data.id
}

output "checkpoint_bucket_name" {
  description = "S3 bucket name for audit checkpoints"
  value       = aws_s3_bucket.checkpoints.id
}

output "checkpoint_bucket_arn" {
  description = "S3 bucket ARN for audit checkpoints"
  value       = aws_s3_bucket.checkpoints.arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms"
  value       = aws_sns_topic.relay_alerts.arn
}

output "relay_domain" {
  description = "Domain name for the relay"
  value       = var.relay_domain
}

output "dns_setup_instructions" {
  description = "Instructions for setting up DNS"
  value = <<-EOT
    DNS Setup Instructions:

    1. Create an A record pointing to the Elastic IP:
       Name: ${var.relay_domain}
       Type: A
       Value: ${aws_eip.relay.public_ip}

    2. Or use CNAME if your registrar supports it:
       Name: ${var.relay_domain}
       Type: CNAME
       Value: ec2-${replace(aws_eip.relay.public_ip, ".", "-")}.compute-1.amazonaws.com

    3. Verify DNS propagation:
       nslookup ${var.relay_domain}

    4. Once DNS resolves, run the provisioning script:
       ./provision-instance.sh ${aws_instance.relay.id} ${var.aws_region}
  EOT
}

output "provision_command" {
  description = "Command to run the provisioning script"
  value       = "cd deploy/aws-provisioning && ./provision-instance.sh ${aws_instance.relay.id} ${var.aws_region}"
}

output "session_manager_command" {
  description = "Command to open a Session Manager session to the instance"
  value       = "aws ssm start-session --target ${aws_instance.relay.id} --region ${var.aws_region}"
}

output "iam_policies" {
  description = "IAM policies created for relay operations"
  value = {
    operator_policy_arn = aws_iam_policy.operator.arn
    restore_policy_arn  = aws_iam_policy.restore_operator.arn
    deploy_policy_arn   = aws_iam_policy.deploy.arn
  }
}

output "instance_profile_name" {
  description = "Instance profile name for the relay instance"
  value       = aws_iam_instance_profile.relay.name
}

output "relay_instance_role_arn" {
  description = "IAM role ARN for the relay instance"
  value       = aws_iam_role.relay_instance.arn
}
