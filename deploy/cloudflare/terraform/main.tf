# One custom domain per environment. workers.dev and preview URLs stay off in
# workers/wrangler.toml, so each Worker answers on exactly this hostname. The
# Worker must already be deployed (the `workers` workflow does it) before
# `terraform apply`, because a custom domain names an existing Worker.
resource "cloudflare_workers_custom_domain" "relay" {
  for_each = var.environments

  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = each.value.hostname
  service    = each.value.worker
}
