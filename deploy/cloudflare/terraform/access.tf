# The admin Worker's only hostname sits behind an Access application that
# requires an operator identity and MFA, and the Worker also verifies Access's
# signed token itself (workers/admin/src/access.js), so a mistake here cannot
# expose it. Nothing is created until admin_environments is set. As with the
# relay, the admin Worker must already be deployed before `terraform apply`,
# because a custom domain names an existing Worker.
locals {
  admin_enabled = length(var.admin_environments) > 0
}

resource "cloudflare_zero_trust_access_policy" "operators" {
  count = local.admin_enabled ? 1 : 0

  account_id = var.account_id
  name       = "keyquorum relay operators (MFA required)"
  decision   = "allow"

  include = [for email in var.operator_emails : { email = { email = email } }]
  require = [{ auth_method = { auth_method = "mfa" } }]

  lifecycle {
    precondition {
      condition     = length(var.operator_emails) > 0
      error_message = "operator_emails must name at least one operator when admin_environments is set."
    }
  }
}

resource "cloudflare_zero_trust_access_application" "admin" {
  for_each = var.admin_environments

  account_id       = var.account_id
  name             = "keyquorum relay admin (${each.key})"
  domain           = each.value.hostname
  type             = "self_hosted"
  session_duration = "1h"

  policies = [{
    id         = cloudflare_zero_trust_access_policy.operators[0].id
    precedence = 1
  }]
}

resource "cloudflare_workers_custom_domain" "admin" {
  for_each = var.admin_environments

  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = each.value.hostname
  service    = each.value.worker
}
