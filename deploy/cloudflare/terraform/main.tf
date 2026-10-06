# The relay is mounted under /relay on its domain, so the same domain can carry
# other things later (the customer app) and a path says what it is:
# https://<hostname>/relay/inbox. A Workers custom domain would take the whole
# hostname, so the relay uses Workers routes for exactly its prefix instead:
# the Worker serves only paths under /relay (workers/src/policy.js) and answers
# 404 to anything else, and these two routes send it nothing else. workers.dev
# stays off, and preview URLs are on only for the public Worker, in
# workers/wrangler.toml.
#
# A route needs the hostname to be proxied (orange-clouded) in the zone's DNS,
# and Terraform does not create that record: add one (for a hostname with no
# site yet, an A record to the placeholder address 192.0.2.1, proxied) before the
# relay can answer. The Worker must already be deployed (the `workers` workflow
# does it) before `terraform apply`, because a route names an existing script.
resource "cloudflare_workers_route" "relay" {
  for_each = var.environments

  zone_id = var.zone_id
  pattern = "${each.value.hostname}/relay/*"
  script  = each.value.worker
}

# `/relay` itself, without a trailing slash, is the status page.
resource "cloudflare_workers_route" "relay_root" {
  for_each = var.environments

  zone_id = var.zone_id
  pattern = "${each.value.hostname}/relay"
  script  = each.value.worker
}
