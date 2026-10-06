variable "account_id" {
  description = "The Cloudflare account that owns the Workers and Access."
  type        = string
}

variable "zone_id" {
  description = "The zone that carries the relay's hostnames."
  type        = string
}

variable "environments" {
  description = "Each environment's public hostname and the Worker that serves it (production is the top-level wrangler configuration, staging is [env.staging])."
  type = map(object({
    hostname = string
    worker   = string
  }))
}

variable "admin_environments" {
  description = "Each environment's admin hostname and the admin Worker that serves it. Every hostname is placed behind an Access application with MFA. Leave empty to create none."
  type = map(object({
    hostname = string
    worker   = string
  }))
  default = {}
}

variable "operator_emails" {
  description = "Operators allowed through the admin Access application (and still required to pass MFA)."
  type        = list(string)
  default     = []
}

variable "rate_limit_requests" {
  description = "Requests allowed per client per period on the customer routes before the edge blocks."
  type        = number
  default     = 600
}

variable "rate_limit_period" {
  description = "The counting period in seconds. Which periods are allowed depends on the Cloudflare plan."
  type        = number
  default     = 60
}

variable "rate_limit_timeout" {
  description = "How long, in seconds, a client stays blocked once it exceeds the limit. Allowed values depend on the plan."
  type        = number
  default     = 60
}

variable "archive_bucket_name" {
  description = "Name of an optional R2 bucket for archival exports. Leave empty to create none."
  type        = string
  default     = ""
}
