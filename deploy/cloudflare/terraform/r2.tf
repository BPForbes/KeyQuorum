# Optional archive for exports. The bucket's retention lock is set in the
# Cloudflare dashboard or API, not here.
resource "cloudflare_r2_bucket" "archive" {
  count = var.archive_bucket_name == "" ? 0 : 1

  account_id = var.account_id
  name       = var.archive_bucket_name
}
