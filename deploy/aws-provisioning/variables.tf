variable "aws_region" {
  description = "AWS region for the relay deployment"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type (t4g.small ~$12/mo for pilot, m7g.medium ~$30/mo for steady load)"
  type        = string
  default     = "t4g.small"

  validation {
    condition     = contains(["t4g.small", "m7g.medium"], var.instance_type)
    error_message = "Instance type must be t4g.small or m7g.medium."
  }
}

variable "root_volume_size" {
  description = "Root volume size in GiB"
  type        = number
  default     = 20
}

variable "data_volume_size" {
  description = "Data volume size in GiB (for /var/lib/keyquorum)"
  type        = number
  default     = 20
}

variable "relay_domain" {
  description = "Domain name for the relay (e.g., relay.example.com)"
  type        = string
}

variable "operator_email" {
  description = "Email for CloudWatch alarm notifications"
  type        = string
}

variable "environment_tag" {
  description = "Environment tag (prod, staging, test)"
  type        = string
  default     = "prod"
}

variable "enable_termination_protection" {
  description = "Enable termination protection on the EC2 instance"
  type        = bool
  default     = true
}

variable "snapshot_retention_days_hourly" {
  description = "Retention period for hourly snapshots (days)"
  type        = number
  default     = 7
}

variable "snapshot_retention_days_daily" {
  description = "Retention period for daily snapshots (days)"
  type        = number
  default     = 90
}

variable "enable_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "kms_key_rotation_enabled" {
  description = "Enable automatic key rotation for the KMS key"
  type        = bool
  default     = true
}

variable "inbound_cidrs" {
  description = "CIDR blocks allowed to reach the relay (default: anywhere)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}

variable "alarm_disk_usage_threshold" {
  description = "Disk usage threshold for CloudWatch alarm (percent)"
  type        = number
  default     = 80
}

variable "alarm_actions_enabled" {
  description = "Enable SNS notifications for CloudWatch alarms"
  type        = bool
  default     = true
}
