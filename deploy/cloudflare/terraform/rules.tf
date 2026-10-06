locals {
  relay_hostnames = [for environment in values(var.environments) : environment.hostname]
  host_match      = "http.host in {${join(" ", [for hostname in local.relay_hostnames : "\"${hostname}\""])}}"
}

# These two rulesets are the zone's rate-limit and cache-settings entry points,
# so applying them replaces any rules already in those phases. Import existing
# ones first if the zone has any (see README.md).
resource "cloudflare_ruleset" "relay_rate_limit" {
  zone_id     = var.zone_id
  name        = "keyquorum relay rate limit"
  description = "Per-client limit on the customer routes, ahead of the Worker's own limit."
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [{
    action      = "block"
    description = "Customer routes: inbox, key check, provider identity"
    enabled     = true
    expression  = "(${local.host_match} and (starts_with(http.request.uri.path, \"/inbox\") or http.request.uri.path eq \"/keycheck\" or http.request.uri.path eq \"/provider-identity\"))"
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = var.rate_limit_period
      requests_per_period = var.rate_limit_requests
      mitigation_timeout  = var.rate_limit_timeout
    }
  }]
}

# Authenticated relay responses must never enter a shared cache: bypass the
# cache for the whole relay hostname, whatever the response headers say.
resource "cloudflare_ruleset" "relay_cache_bypass" {
  zone_id     = var.zone_id
  name        = "keyquorum relay cache bypass"
  description = "Never cache anything the relay answers."
  kind        = "zone"
  phase       = "http_request_cache_settings"

  rules = [{
    action      = "set_cache_settings"
    description = "Bypass the cache on the relay hostnames"
    enabled     = true
    expression  = local.host_match
    action_parameters = {
      cache = false
    }
  }]
}
