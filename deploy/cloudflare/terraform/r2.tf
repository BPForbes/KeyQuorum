# Optional archive for exports. The bucket's retention lock is set in the
# Cloudflare dashboard or API, not here.
resource "cloudflare_r2_bucket" "archive" {
  count = var.archive_bucket_name == "" ? 0 : 1

  account_id = var.account_id
  name       = var.archive_bucket_name
}

# The relay's sealed letters (docs/operator/r2-blobs.md): one private bucket per
# environment, bound to the public Worker as LETTERS (workers/wrangler.toml).
# They must exist before the first deploy, and the names must be the ones the
# Worker's configuration binds. A bucket is private until a public-access or a
# custom-domain resource is added for it, and none is: the relay serves every
# letter through its authenticated routes, and the objects are sealed to their
# recipients in any case. Nothing here sets retention: the relay deletes an
# object when the letter's row goes (expiry, a failed upload, a purge), and a
# retention lock would stop that.
resource "cloudflare_r2_bucket" "letters" {
  count = var.letters_bucket_name == "" ? 0 : 1

  account_id = var.account_id
  name       = var.letters_bucket_name
}

resource "cloudflare_r2_bucket" "letters_staging" {
  count = var.letters_bucket_name_staging == "" ? 0 : 1

  account_id = var.account_id
  name       = var.letters_bucket_name_staging
}
