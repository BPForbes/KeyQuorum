output "relay_urls" {
  description = "The relay's URL in each environment, as a client is given it (the GitHub environment variable RELAY_URL)."
  value       = { for name, environment in var.environments : name => "https://${environment.hostname}/relay" }
}

output "admin_urls" {
  description = "The admin Worker's Access-protected URL for each environment."
  value       = { for name, environment in var.admin_environments : name => "https://${environment.hostname}" }
}

output "admin_access_aud" {
  description = "Each admin Access application's audience tag. Set it as the GitHub environment variable ACCESS_AUD; the admin Worker refuses any token not issued for it."
  value       = { for name, application in cloudflare_zero_trust_access_application.admin : name => application.aud }
}
