terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Environment = var.environment_tag
        ManagedBy   = "Terraform"
        Application = "KeyQuorum-Relay"
      },
      var.tags
    )
  }
}

# Get the latest Ubuntu 24.04 LTS ARM image
data "aws_ami" "ubuntu_arm" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# KMS key for EBS encryption
resource "aws_kms_key" "ebs" {
  description             = "KMS key for KeyQuorum relay EBS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = var.kms_key_rotation_enabled

  tags = {
    Name = "keyquorum-relay-ebs"
  }
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/keyquorum-relay-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

# Enable EBS encryption by default for this account
resource "aws_ec2_ebs_encryption_by_default" "enabled" {
  enabled = true
}

# Set the default KMS key for EBS encryption
resource "aws_ec2_ebs_default_kms_key" "default" {
  kms_key_id = aws_kms_key.ebs.arn
}

# Elastic IP for stable public address
resource "aws_eip" "relay" {
  domain   = "vpc"
  instance = aws_instance.relay.id

  tags = {
    Name = "keyquorum-relay-eip"
  }

  depends_on = [aws_instance.relay]
}

# EC2 instance for the relay
resource "aws_instance" "relay" {
  ami                    = data.aws_ami.ubuntu_arm.id
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.relay.name
  monitoring             = var.enable_monitoring
  disable_api_termination = var.enable_termination_protection

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = aws_kms_key.ebs.arn
    tags = {
      Name = "keyquorum-relay-root"
    }
  }

  vpc_security_group_ids = [aws_security_group.relay.id]
  user_data              = base64encode(local.user_data_script)

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "keyquorum-relay"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = {
      Name = "keyquorum-relay-root"
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring = var.enable_monitoring

  lifecycle {
    ignore_changes = [user_data]
  }
}

# Data volume for the relay database (encrypted)
resource "aws_ebs_volume" "relay_data" {
  availability_zone   = aws_instance.relay.availability_zone
  size                = var.data_volume_size
  type                = "gp3"
  encrypted           = true
  kms_key_id          = aws_kms_key.ebs.arn
  iops                = 3000
  throughput          = 125

  tags = {
    Name = "keyquorum-relay-data"
  }

  depends_on = [aws_instance.relay]
}

# Attach the data volume to the instance
resource "aws_volume_attachment" "relay_data" {
  device_name             = "/dev/sdf"
  volume_id               = aws_ebs_volume.relay_data.id
  instance_id             = aws_instance.relay.id
  delete_on_termination   = false  # Preserve on termination
  skip_destroy            = true
}

# CloudWatch alarm for disk usage (will be updated after provisioning)
resource "aws_cloudwatch_metric_alarm" "disk_usage" {
  alarm_name          = "keyquorum-relay-disk-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DiskUsagePercent"
  namespace           = "KeyQuorum/Relay"
  period              = "300"
  statistic           = "Average"
  threshold           = var.alarm_disk_usage_threshold
  alarm_description   = "Alert when relay data volume exceeds ${var.alarm_disk_usage_threshold}% usage"
  alarm_actions       = var.alarm_actions_enabled && aws_sns_topic.relay_alerts.arn != "" ? [aws_sns_topic.relay_alerts.arn] : []

  dimensions = {
    InstanceId = aws_instance.relay.id
  }

  tags = {
    Name = "keyquorum-relay-disk-usage"
  }
}

# CloudWatch alarm for instance state
resource "aws_cloudwatch_metric_alarm" "instance_state" {
  alarm_name          = "keyquorum-relay-instance-state"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alert if relay instance fails status checks"
  alarm_actions       = var.alarm_actions_enabled && aws_sns_topic.relay_alerts.arn != "" ? [aws_sns_topic.relay_alerts.arn] : []

  dimensions = {
    InstanceId = aws_instance.relay.id
  }

  tags = {
    Name = "keyquorum-relay-instance-state"
  }
}

# SNS topic for CloudWatch alarms
resource "aws_sns_topic" "relay_alerts" {
  name = "keyquorum-relay-alerts"

  tags = {
    Name = "keyquorum-relay-alerts"
  }
}

# SNS topic subscription for email
resource "aws_sns_topic_subscription" "relay_alerts_email" {
  topic_arn = aws_sns_topic.relay_alerts.arn
  protocol  = "email"
  endpoint  = var.operator_email
}

# S3 bucket for audit checkpoints (write-once with Object Lock)
resource "aws_s3_bucket" "checkpoints" {
  bucket = "keyquorum-relay-checkpoints-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name = "keyquorum-relay-checkpoints"
  }
}

resource "aws_s3_bucket_versioning" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ebs.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# EBS Snapshot Lifecycle Policy (hourly snapshots)
resource "aws_dlm_lifecycle_policy" "snapshots_hourly" {
  description        = "Hourly snapshots of KeyQuorum relay data volume (7 day retention)"
  execution_role_arn = aws_iam_role.dlm.arn
  state               = "ENABLED"

  policy_details {
    policy_type = "EBS_SNAPSHOT_MANAGEMENT"

    resource_types = ["VOLUME"]

    schedule {
      name = "hourly-snapshots"

      create_rule {
        interval      = 1
        interval_unit = "HOURS"
      }

      retain_rule {
        count = 168  # 7 days * 24 hours
      }

      tag_specifications {
        resource_type = "snapshot"
        resources_to_add = {
          Name = "keyquorum-relay-hourly"
        }
      }

      fast_restore_rule {
        count = 3
      }
    }

    target_tags = {
      SnapshotSchedule = "hourly"
    }
  }

  tags = {
    Name = "keyquorum-relay-hourly-snapshots"
  }
}

# Daily snapshots (optional, longer retention)
resource "aws_dlm_lifecycle_policy" "snapshots_daily" {
  description        = "Daily snapshots of KeyQuorum relay data volume (90 day retention)"
  execution_role_arn = aws_iam_role.dlm.arn
  state               = "ENABLED"

  policy_details {
    policy_type = "EBS_SNAPSHOT_MANAGEMENT"

    resource_types = ["VOLUME"]

    schedule {
      name = "daily-snapshots"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["00:00"]
      }

      retain_rule {
        count = 90
      }

      tag_specifications {
        resource_type = "snapshot"
        resources_to_add = {
          Name = "keyquorum-relay-daily"
        }
      }
    }

    target_tags = {
      SnapshotSchedule = "daily"
    }
  }

  tags = {
    Name = "keyquorum-relay-daily-snapshots"
  }
}

# Tag the data volume for snapshot scheduling
resource "aws_ec2_tag" "data_volume_hourly" {
  resource_id = aws_ebs_volume.relay_data.id
  key         = "SnapshotSchedule"
  value       = "hourly"

  depends_on = [aws_volume_attachment.relay_data]
}

resource "aws_ec2_tag" "data_volume_daily" {
  resource_id = aws_ebs_volume.relay_data.id
  key         = "SnapshotSchedule"
  value       = "daily"

  depends_on = [aws_volume_attachment.relay_data]
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# Local variables
locals {
  user_data_script = templatefile("${path.module}/user-data.sh", {
    data_volume_device = "/dev/nvme1n1"
    data_mount_point   = "/var/lib/keyquorum"
  })
}
