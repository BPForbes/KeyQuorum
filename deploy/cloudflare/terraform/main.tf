# The relay and the console are mounted under paths of one domain, so that the
# same domain can carry other things later (the customer app) and a path says
# what each thing is:
#   keyquorum.dev/relay                      the production relay
#   keyquorum.dev/relay/staging-user         the staging relay
#   keyquorum.dev/relay/admin                the production console (Access)
#   keyquorum.dev/relay/staging-admin        the staging console (Access)
# A Workers custom domain would take a whole hostname, so each Worker gets
# Workers routes for exactly its path instead; where two routes overlap
# (`/relay/*` and `/relay/staging-user/*`) Cloudflare uses the more specific one
# (from memory, verify at the first apply). Each Worker serves only below its own
# mount (workers/src/mount.js, set by MOUNT_PATH, which the deploy takes from the
# same URL as this path) and answers 404 to anything else, so a request that
# reaches the wrong Worker gets nothing. workers.dev stays off, and preview URLs
# are on only for the public Worker, in workers/wrangler.toml.
#
# A route needs the hostname to be proxied (orange-clouded) in the zone's DNS,
# and Terraform does not create that record: add one (for a hostname with no
# site yet, an A record to the placeholder address 192.0.2.1, proxied) before the
# relay can answer. The Worker must already be deployed (the `workers` workflow
# does it) before `terraform apply`, because a route names an existing script.
resource "cloudflare_workers_route" "relay" {
  for_each = var.environments

  zone_id = var.zone_id
  pattern = "${each.value.hostname}${each.value.path}/*"
  script  = each.value.worker
}

# The mount itself, without a trailing slash, which the Worker sends to the slash.
resource "cloudflare_workers_route" "relay_root" {
  for_each = var.environments

  zone_id = var.zone_id
  pattern = "${each.value.hostname}${each.value.path}"
  script  = each.value.worker
}
