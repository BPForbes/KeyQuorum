# The API token comes from the CLOUDFLARE_API_TOKEN environment variable of the
# operator running `terraform apply`; it is never a variable, a file in this
# directory, or a GitHub secret. See README.md for the scopes it needs.
provider "cloudflare" {}
