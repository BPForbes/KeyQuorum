# Cloudflare infrastructure for the relay

Infrastructure as code for the parts of the relay's hosting that live in
Cloudflare outside the Worker code: custom domains, the edge rate limit, the
cache bypass, the Access application for the admin Worker and an optional R2
archive bucket. The plan of record is `docs/operator/relay-hosting.md`; this
directory is an operator document, not customer-facing.

Status: the Workers relay is not built yet. Stage 2 deploys a health-only stub
(`workers/`), so this directory can be applied and checked before the relay
exists. CI runs `terraform fmt -check` and `terraform validate` on every pull
request (the `terraform` job of `.github/workflows/workers.yml`); nothing here
has been applied to a real account by the repository's authors.

## Who runs it, and with what

The operator runs `terraform plan` and `terraform apply` from their own machine
with their own Cloudflare credentials. Those credentials never go into GitHub,
a variable file in this directory, or an agent session.

- `CLOUDFLARE_API_TOKEN` in the environment of the shell that runs Terraform.
  Scope it to what this directory manages (from memory, verify against the
  token UI): Workers Scripts and Workers Routes or Custom Domains edit, Zone
  Rulesets and Zone Settings edit, Access Apps and Policies edit, Account R2
  edit when an archive bucket is used. It is a different token from the
  Workers-deploy token that GitHub holds (Workers Scripts edit only).
- `terraform.tfvars`, copied from `terraform.tfvars.example`. It is ignored by
  git. It holds identifiers and hostnames, not secrets.
- State is local by default and is ignored by git (`*.tfstate`). It records
  resource attributes, so keep it off shared drives and out of backups you do
  not control. A remote backend is a decision for the operator, not made here.

## Order of operations

1. Deploy the Worker first: the `workers` workflow does it on a push to `main`
   (or `npx wrangler deploy --env staging` from `workers/`). A custom domain
   names an existing Worker, so `apply` fails before this.
2. `terraform init`, `terraform plan`, review, `terraform apply`.
3. Set the GitHub environment variable `RELAY_URL` for each environment to the
   hostname the plan created, so the smoke test and the environment link work.
4. Set the Worker secrets (relay key, certificate, revocation list) locally with
   `wrangler secret put`. Terraform never sees them.

## Things to know before applying

- `relay_rate_limit` and `relay_cache_bypass` are the zone's entry-point
  rulesets for the `http_ratelimit` and `http_request_cache_settings` phases.
  Applying them replaces any rules already in those phases, so import existing
  ones first (`terraform import`) if the zone has any.
- The rate-limit counting periods and block timeouts that are allowed depend on
  the Cloudflare plan; the defaults are meant to suit the lowest plan (from
  memory, verify). Tune them in `terraform.tfvars`.
- `auth_method = "mfa"` in the Access policy relies on the identity provider
  reporting that MFA was used (from memory, verify for your provider). Test the
  admin Access application with an operator who has no MFA before relying on it.
- The admin Access application is created only when `admin_hostname` is set,
  and there is no admin Worker yet.
- Not managed here yet: Cloudflare Notifications (Worker and Durable Object error
  alerts) and the R2 bucket's retention lock. They are set in the dashboard until
  a validated resource for them is added.
- CI's `terraform validate` accepts this configuration against provider 5.27.0,
  which the committed `.terraform.lock.hcl` pins (`init -lockfile=readonly`, so a
  changed selection fails CI; Dependabot proposes provider updates). Validation
  checks the configuration's shape, not the account: it has never been planned
  or applied against a real Cloudflare account, so expect the first `plan` to
  surface plan-time checks the validator cannot make.
