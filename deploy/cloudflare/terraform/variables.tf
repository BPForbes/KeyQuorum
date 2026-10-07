variable "account_id" {
  description = "The Cloudflare account that owns the Workers and Access."
  type        = string
}

variable "zone_id" {
  description = "The zone that carries the relay's and the console's hostnames (the zone of the domain, for example keyquorum.dev)."
  type        = string
}

variable "environments" {
  description = "Each environment's hostname (the bare domain, no path), the path the relay Worker is mounted under (/relay, or /relay/<name> for a staging relay on the same host; a name that is not one of the relay's own routes) and the Worker that serves it (production is the top-level wrangler configuration, staging is [env.staging]). The path is also the path of RELAY_URL."
  type = map(object({
    hostname = string
    path     = string
    worker   = string
  }))

  validation {
    condition = alltrue([
      for environment in values(var.environments) :
      can(regex("^/relay(/[a-z0-9]+(-[a-z0-9]+)*)?$", environment.path)) &&
      !contains(["inbox", "keycheck", "provider-identity", "audit", "trees", "devices", "health", "ready", "assets"], try(regex("^/relay/(.+)$", environment.path)[0], ""))
    ])
    error_message = "Each relay path must be /relay or /relay/<name> (lowercase letters, digits and single hyphens), and the name must not be one of the relay's own routes."
  }
}

variable "admin_environments" {
  description = "Each environment's console: its hostname (no path), the path the admin Worker is mounted under (/relay/<name>, never /relay itself) and the Worker. Every one is placed behind an Access application. Leave empty to create none. The path is also the path of ADMIN_URL."
  type = map(object({
    hostname = string
    path     = string
    worker   = string
  }))
  default = {}

  validation {
    condition = alltrue([
      for environment in values(var.admin_environments) :
      can(regex("^/relay/[a-z0-9]+(-[a-z0-9]+)*$", environment.path)) &&
      !contains(["inbox", "keycheck", "provider-identity", "audit", "trees", "devices", "health", "ready", "assets"], try(regex("^/relay/(.+)$", environment.path)[0], ""))
    ])
    error_message = "Each console path must be /relay/<name> (lowercase letters, digits and single hyphens), not /relay itself and not one of the relay's own route names."
  }
}

variable "idp_mfa_required" {
  description = "Require that the identity provider reports MFA (auth_method = mfa). Only for Okta, Entra ID, generic OIDC or generic SAML; with one-time PIN, the Cloudflare identity provider or Sign in with Apple leave it false and turn on Access's independent MFA with a security key instead."
  type        = bool
  default     = false
}

variable "operator_emails" {
  description = "Operators allowed through the admin Access application. The second factor is Access's independent MFA (a Zero Trust setting), or idp_mfa_required for an IdP that reports it."
  type        = list(string)
  default     = []
}

variable "rate_limit_requests" {
  description = "Requests allowed per client IP and data centre per period on the paths under /relay before the edge blocks (Free zone plan: 10-second period and block)."
  type        = number
  default     = 100
}

variable "rate_limit_period" {
  description = "The counting period in seconds. Which periods are allowed depends on the Cloudflare plan."
  type        = number
  default     = 10
}

variable "rate_limit_timeout" {
  description = "How long, in seconds, a client stays blocked once it exceeds the limit. Allowed values depend on the plan."
  type        = number
  default     = 10
}

variable "archive_bucket_name" {
  description = "Name of an optional R2 bucket for archival exports. Leave empty to create none."
  type        = string
  default     = ""
}

variable "letters_bucket_name" {
  description = "Name of the production R2 bucket for sealed letters; the Worker binds it as LETTERS (workers/wrangler.toml names keyquorum-letters). Leave empty to create none."
  type        = string
  default     = ""
}

variable "letters_bucket_name_staging" {
  description = "Name of the staging R2 bucket for sealed letters (workers/wrangler.toml names keyquorum-letters-staging). Never the production bucket. Leave empty to create none."
  type        = string
  default     = ""
}
