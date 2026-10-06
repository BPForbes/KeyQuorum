locals {
  relay_hostnames = [for environment in values(var.environments) : environment.hostname]
  host_match      = "http.host in {${join(" ", [for hostname in local.relay_hostnames : "\"${hostname}\""])}}"
  # The relay is only what is under /relay on those hostnames; the rest of the
  # domain (the customer app, later) is not covered by these two rulesets.
  relay_match = "(${local.host_match} and (http.request.uri.path eq \"/relay\" or starts_with(http.request.uri.path, \"/relay/\")))"
}

# These two rulesets are the zone's rate-limit and cache-settings entry points,
# so applying them replaces any rules already in those phases. Import existing
# ones first if the zone has any (see README.md).
resource "cloudflare_ruleset" "relay_rate_limit" {
  zone_id     = var.zone_id
  name        = "keyquorum relay rate limit"
  description = "Per-client limit on every route under /relay (the relay's and the console's) except a health check, ahead of the Worker's own limit."
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [{
    action      = "block"
    description = "Every route under /relay except a health check"
    enabled     = true
    # Free plans allow Path, but not Host, in a rate-limit expression.
    # This applies to /relay on every hostname in this dedicated zone.
    expression  = "((http.request.uri.path eq \"/relay\" or starts_with(http.request.uri.path, \"/relay/\")) and not ends_with(http.request.uri.path, \"/health\"))"
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = var.rate_limit_period
      requests_per_period = var.rate_limit_requests
      mitigation_timeout  = var.rate_limit_timeout
    }
  }]
}

# Authenticated relay responses must never enter a shared cache: bypass the
# cache for everything under /relay, whatever the response headers say.
resource "cloudflare_ruleset" "relay_cache_bypass" {
  zone_id     = var.zone_id
  name        = "keyquorum relay cache bypass"
  description = "Never cache anything the relay answers."
  kind        = "zone"
  phase       = "http_request_cache_settings"

  rules = [{
    action      = "set_cache_settings"
    description = "Bypass the cache under /relay on the relay hostnames"
    enabled     = true
    expression  = local.relay_match
    action_parameters = {
      cache = false
    }
  }]
}
