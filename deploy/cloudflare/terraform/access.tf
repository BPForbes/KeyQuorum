# The admin Worker's only path sits behind an Access application that
# requires an operator identity (the policy below), and the Worker also
# verifies Access's signed token itself (workers/admin/src/access.js), so a mistake here cannot
# expose it. Nothing is created until admin_environments is set. As with the
# relay, the admin Worker must already be deployed before `terraform apply`,
# because a custom domain names an existing Worker.
locals {
  admin_enabled = length(var.admin_environments) > 0
}

resource "cloudflare_zero_trust_access_policy" "operators" {
  count = local.admin_enabled ? 1 : 0

  account_id = var.account_id
  name       = "keyquorum relay operators"
  decision   = "allow"

  include = [for email in var.operator_emails : { email = { email = email } }]

  # Identity-provider MFA (the IdP reports it) works only with Okta, Entra ID,
  # generic OIDC and generic SAML. With one-time PIN, the Cloudflare identity
  # provider or Sign in with Apple it can never be satisfied and would lock the
  # operator out, so it is off unless idp_mfa_required is set. The second
  # factor for those logins is Access's independent MFA, a Zero Trust setting
  # (a security key, enrolled in the App Launcher) that this repository cannot
  # create or verify: see README.md, "Operator login and MFA".
  require = [for n in range(var.idp_mfa_required ? 1 : 0) : { auth_method = { auth_method = "mfa" } }]

  lifecycle {
    precondition {
      condition     = length(var.operator_emails) > 0
      error_message = "operator_emails must name at least one operator when admin_environments is set."
    }
  }
}

resource "cloudflare_zero_trust_access_application" "admin" {
  for_each = var.admin_environments

  account_id = var.account_id
  name       = "keyquorum relay admin (${each.key})"
  # The console's mount: its hostname and path, and everything below it (from
  # memory, verify at the first apply that Access takes a path with a trailing
  # wildcard here). The admin Worker verifies the Access token itself, so a path
  # this does not cover is still refused without a valid token.
  domain           = "${each.value.hostname}${each.value.path}/*"
  type             = "self_hosted"
  session_duration = "1h"

  policies = [{
    id         = cloudflare_zero_trust_access_policy.operators[0].id
    precedence = 1
  }]
}

# The console's routes, as for the relay (main.tf): its path below the host.
resource "cloudflare_workers_route" "admin" {
  for_each = var.admin_environments

  zone_id = var.zone_id
  pattern = "${each.value.hostname}${each.value.path}/*"
  script  = each.value.worker
}

resource "cloudflare_workers_route" "admin_root" {
  for_each = var.admin_environments

  zone_id = var.zone_id
  pattern = "${each.value.hostname}${each.value.path}"
  script  = each.value.worker
}
