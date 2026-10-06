# Cloudflare infrastructure for the relay

Infrastructure as code for the parts of the relay's hosting that live in
Cloudflare outside the Worker code: custom domains, the edge rate limit, the
cache bypass, the Access application for the admin Worker and an optional R2
archive bucket. The plan of record is `docs/operator/relay-hosting.md`; this
directory is an operator document, not customer-facing.

Status: the Workers relay is not built yet. Stage 2 deploys a health-only stub
(`workers/`), so this directory can be applied and checked before the relay
exists, and stage 4a adds the admin Worker's front door (`workers/admin/`, a
static page behind Access that only shows who is signed in). CI runs
`terraform fmt -check` and `terraform validate` on every pull request (the
`terraform` job of `.github/workflows/workers.yml`); nothing here has been
applied to a real account by the repository's authors.

The relay uses a separate Cloudflare domain dedicated to it (owner decision,
2026-10-06), not bailey-forbes.com: `zone_id` and every hostname below belong to
that zone, and the portfolio's DNS and hosting are not touched by anything in
this directory.

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
  git. It holds identifiers, hostnames and the operators' email addresses, not
  secrets. Its variables:
  - `account_id`, `zone_id`: the account and the dedicated relay zone.
  - `environments`: a map of `{hostname, worker}`, the public relay Worker's
    custom domain per environment.
  - `admin_environments`: a map of `{hostname, worker}` for the admin Worker
    (`keyquorum-relay-admin`, `keyquorum-relay-admin-staging`), empty by
    default. It replaces the earlier single `admin_hostname`. For each entry
    Terraform creates a custom domain for the admin Worker and a self-hosted
    Access application (1 hour session) for that hostname; all of them share
    one allow policy.
  - `operator_emails`: the operators the policy allows. MFA is required of
    them as well (`auth_method = "mfa"`). Setting `admin_environments` with no
    operator email fails the plan (a precondition).
  - `rate_limit_requests`, `rate_limit_period`, `rate_limit_timeout`,
    `archive_bucket_name`: see the variable descriptions.
- Outputs: `relay_urls`, `admin_urls` (the Access-protected URL per admin
  environment) and `admin_access_aud` (each Access application's audience tag).
  The audience tag is not a secret. The admin Worker accepts only tokens issued
  for it.
- The Access application needs a Zero Trust organisation on the account. Create
  it in the dashboard first; its team domain (of the form `<team>.cloudflareaccess.com`, from memory,
  verify) is shown there and is not a Terraform output.
- State is local by default and is ignored by git (`*.tfstate`). It records
  resource attributes, so keep it off shared drives and out of backups you do
  not control. A remote backend is a decision for the operator, not made here.

## Order of operations

1. Create the Zero Trust organisation in the dashboard (once), and note its team
   domain.
2. Deploy the Workers first: the `workers` workflow deploys the public Worker
   and the admin Worker on a push to `main` (or `npx wrangler deploy --env
   staging` from `workers/`, and `npx wrangler deploy -c admin/wrangler.toml
   --env staging`). A custom domain names an existing Worker, so `apply` fails
   before this. Until the Access variables below are set the admin Worker is
   deployed unconfigured and serves nothing (503), which is the safe state.
   Once the public Worker exists it can be connected to Cloudflare Workers
   Builds for the pull-request check and Previews, the way the portfolio site
   is (`docs/operator/relay-hosting.md`, "Workers Builds and previews"); that
   connection deploys nothing on `main` and needs nothing from this directory.
3. Set `operator_emails` and `admin_environments` in `terraform.tfvars`, then
   `terraform init`, `terraform plan`, review, `terraform apply`.
4. Set the GitHub environment variable `RELAY_URL` for each environment to the
   hostname the plan created, so the smoke test and the environment link work.
5. Set the admin Worker's Access settings as GitHub environment variables (not
   secrets) in each environment: `ACCESS_AUD` from `terraform output
   admin_access_aud` (the entry for that environment), `ACCESS_TEAM_DOMAIN`
   from the Zero Trust dashboard, and `ADMIN_URL` from `terraform output
   admin_urls` (the smoke test then requires an anonymous request to it to be a
   redirect or a refusal). Run the `workers` workflow again so the admin Worker
   is deployed with them.
6. Set the Worker secrets (relay key, certificate, revocation list) locally with
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
- The admin custom domains and Access applications are created only when
  `admin_environments` is set. No route bypasses Access: the hostname sits
  behind the application, and the admin Worker also verifies Access's token
  itself (`workers/admin/src/access.js`), so a mistake in the policy does not
  serve the page. Today the page only shows who is signed in; the relay-backed
  pages and the Worker's binding to the Durable Object are not built (stage 4).
- CI's `terraform validate` also accepts the resources behind `admin_environments`
  and the `admin_access_aud` output (the `terraform` job on commit `86bbb8f`);
  nothing here has been planned or applied against a real account.
- Not managed here yet: Cloudflare Notifications (Worker and Durable Object error
  alerts) and the R2 bucket's retention lock. They are set in the dashboard until
  a validated resource for them is added.
- CI's `terraform validate` accepts this configuration against provider 5.27.0,
  which the committed `.terraform.lock.hcl` pins (`init -lockfile=readonly`, so a
  changed selection fails CI; Dependabot proposes provider updates). Validation
  checks the configuration's shape, not the account: it has never been planned
  or applied against a real Cloudflare account, so expect the first `plan` to
  surface plan-time checks the validator cannot make.
