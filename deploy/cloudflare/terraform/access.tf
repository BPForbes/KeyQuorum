# The admin Worker's only hostname sits behind an Access application that
# requires an operator identity and MFA. Nothing is created until
# admin_hostname is set, because the admin Worker does not exist yet.
resource "cloudflare_zero_trust_access_policy" "operators" {
  count = var.admin_hostname == "" ? 0 : 1

  account_id = var.account_id
  name       = "keyquorum relay operators (MFA required)"
  decision   = "allow"

  include = [for email in var.operator_emails : { email = { email = email } }]
  require = [{ auth_method = { auth_method = "mfa" } }]
}

resource "cloudflare_zero_trust_access_application" "admin" {
  count = var.admin_hostname == "" ? 0 : 1

  account_id       = var.account_id
  name             = "keyquorum relay admin"
  domain           = var.admin_hostname
  type             = "self_hosted"
  session_duration = "1h"

  policies = [{
    id         = cloudflare_zero_trust_access_policy.operators[0].id
    precedence = 1
  }]
}
