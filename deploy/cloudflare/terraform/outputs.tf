output "relay_urls" {
  description = "The public URL of each environment."
  value       = { for name, environment in var.environments : name => "https://${environment.hostname}" }
}

output "admin_url" {
  description = "The admin Worker's Access-protected URL, if one is configured."
  value       = var.admin_hostname == "" ? null : "https://${var.admin_hostname}"
}
