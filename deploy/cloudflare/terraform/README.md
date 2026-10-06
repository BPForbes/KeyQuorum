# Cloudflare infrastructure for the relay

Infrastructure as code for the parts of the relay's hosting that live in
Cloudflare outside the Worker code: the relay's routes, the edge rate limit, the
cache bypass, the Access application for the admin Worker and an optional R2
archive bucket. The plan of record is `docs/operator/relay-hosting.md`; this
directory is an operator document, not customer-facing.

Status: the public Worker and its Durable Object (`workers/`) are built and
tested but have never been deployed, and the admin Worker's back end that would
mint customer keys is not built, so no customer can use the relay yet. Stage 4a
adds the admin Worker's front door (`workers/admin/`, a static page behind
Access that only shows who is signed in). CI runs `terraform fmt -check` and
`terraform validate` on every pull request (the `terraform` job of
`.github/workflows/workers.yml`); nothing here has been applied to a real
account by the repository's authors.

The relay uses the owner's domain `keyquorum.dev` (owner decision, 2026-10-06,
replacing the earlier `bailey-forbes.com` plan: that domain's DNS is not on
Cloudflare, and a Worker can only be served on a zone that is). `zone_id` is
`keyquorum.dev`'s zone, so the domain must be a zone on the owner's Cloudflare
account: add it in the dashboard and change its nameservers at the registrar to
the two Cloudflare gives, or register or transfer it to Cloudflare. The domain
is meant to carry more than the relay (a customer app, later), so everything
here is mounted under paths of that one hostname, through Workers routes
(`main.tf`, `access.tf`), not custom domains (a custom domain takes a whole
hostname):

| Path on `keyquorum.dev` | What | Worker |
| --- | --- | --- |
| `/relay` | the production relay | `keyquorum-relay` |
| `/relay/staging-user` | the staging relay | `keyquorum-relay-staging` |
| `/relay/admin` | the production console (behind Access) | `keyquorum-relay-admin` |
| `/relay/staging-admin` | the staging console (behind Access) | `keyquorum-relay-admin-staging` |

Each Worker serves only below its own path (`workers/src/mount.js`, set by its
`MOUNT_PATH`, which the deploy takes from the path of `RELAY_URL` or
`ADMIN_URL`) and answers 404 to anything else, and where two routes overlap
Cloudflare uses the more specific one (from memory, verify at the first apply).
The two rulesets in `rules.tf` match only paths under `/relay`.
**One origin carries all four**, the console and the customer app (later)
included, which the earlier plan of a hostname of its own for the console
avoided: see "One origin" below. `rules.tf` manages
the zone's rate-limit and cache-settings entry-point rulesets and **replaces any
rules already in those two phases**, which matters only if the zone already has
some: look in the dashboard first (Security, WAF, Rate limiting rules; Caching,
Cache Rules) and import what exists before `terraform apply`.

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
  - `account_id`, `zone_id`: the account and the domain's zone.
  - `environments`: a map of `{hostname, path, worker}`: the hostname (the bare
    domain, no path), the path the public relay Worker is mounted under
    (`/relay`, or `/relay/<name>`; the name may not be one of the relay's own
    routes, which a validation checks) and the Worker. It is also the path of
    `RELAY_URL`.
  - `admin_environments`: a map of `{hostname, path, worker}` for the admin
    Worker (`keyquorum-relay-admin`, `keyquorum-relay-admin-staging`), empty by
    default. The path is `/relay/<name>`, never `/relay` itself, and is also the
    path of `ADMIN_URL`. For each entry Terraform creates routes for the admin
    Worker and a self-hosted Access application (1 hour session) for that
    hostname and path; all of them share one allow policy.
  - `operator_emails`: the operators the policy allows (the email the login
    asserts must match exactly). Setting `admin_environments` with no operator
    email fails the plan (a precondition).
  - `idp_mfa_required` (default `false`): also require that the identity
    provider reports MFA. Only Okta, Entra ID, generic OIDC and generic SAML can
    report it; with one-time PIN, the Cloudflare identity provider or Sign in
    with Apple it would lock the operator out. The second factor for those is
    independent MFA, below.
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
2. Choose the hostname and paths in `terraform.tfvars` (`environments`, and
   `admin_environments` later). Add a proxied (orange-clouded) DNS record for the
   hostname, which Terraform does not create (for a hostname with no site yet, an
   A record to the placeholder address 192.0.2.1). Set the GitHub environment
   variable `RELAY_URL` in each environment to `https://<hostname><path>` (for
   staging `https://keyquorum.dev/relay/staging-user`: the URL a client is
   given; the scripts refuse any other path) **before the first deploy**. The
   deploy passes its host to the Worker as `ALLOWED_HOSTS`, and the Worker
   serves that host and no other, so a Worker deployed without it serves
   nothing (staging warns and deploys that way; production refuses to deploy).
3. Deploy the Workers: the `workers` workflow deploys the public Worker and the
   admin Worker on a push to `main` (or, from `workers/`, `npm run
   build:relay-wasm` and then `npx wrangler deploy --env staging --var
   ALLOWED_HOSTS:<host>`, and `npx wrangler deploy -c admin/wrangler.toml --env
   staging`). A route names an existing Worker, so `apply` fails before
   this. Until the Access variables below are set the admin Worker is deployed
   unconfigured and serves nothing (503), which is the safe state. Once the
   public Worker exists it can be connected to Cloudflare Workers Builds for the
   pull-request check and Previews, the way the portfolio site is
   (`docs/operator/relay-hosting.md`, "Workers Builds and previews"); that
   connection deploys nothing on `main` and needs nothing from this directory.
4. Set `operator_emails` and `admin_environments` in `terraform.tfvars`, then
   `terraform init`, `terraform plan`, review, `terraform apply`. Check that
   `terraform output relay_urls` shows the same URLs as `RELAY_URL`; if
   they differ, fix `RELAY_URL` and deploy again.
5. Set the admin Worker's Access settings as GitHub environment variables (not
   secrets) in each environment: `ACCESS_AUD` from `terraform output
   admin_access_aud` (the entry for that environment), `ACCESS_TEAM_DOMAIN`
   from the Zero Trust dashboard, and `ADMIN_URL` from `terraform output
   admin_urls` (the smoke test then requires an anonymous request to it to be a
   redirect or a refusal). Run the `workers` workflow again so the admin Worker
   is deployed with them.
6. Set the Worker secrets (relay key and certificate) locally with `wrangler
   secret put`, as `docs/operator/relay-deployment.md` shows. Terraform never
   sees them.

## Things to know before applying

- `relay_rate_limit` and `relay_cache_bypass` are the zone's entry-point
  rulesets for the `http_ratelimit` and `http_request_cache_settings` phases.
  Applying them replaces any rules already in those phases, so import existing
  ones first (`terraform import`) if the zone has any.
- The edge rate-limit defaults support the Free zone plan: 100 requests per
  client IP and data center per 10 seconds, then block for 10 seconds. Free
  rate-limit expressions can match Path but not Host, so this rule covers
  `/relay` and its descendants on every hostname in this dedicated zone (except
  paths ending in `/health`). The cache-bypass rule still matches only the
  configured relay hostnames. Longer counting or blocking windows require a
  paid zone plan; do not upgrade without the owner\'s approval. These limits
  constrain short bursts; they are not an exact 600-request rolling minute.
  Source: [Cloudflare rate limiting availability](https://developers.cloudflare.com/waf/rate-limiting-rules/#availability), read 2026-10-06.
- **Operator login and MFA.** Terraform creates the Access application and an
  allow policy for `operator_emails`; it does **not** create or verify the
  second factor. The recommended setup (a decision of the owner, 2026-10-06) is
  login by the Cloudflare identity provider or a one-time PIN to the operator's
  own address, plus Access's **independent MFA** with a hardware security key:
  in Zero Trust, Access controls, Access settings, under "Allow multi-factor
  authentication (MFA)" allow **Security key** (and, if you accept it, nothing
  weaker), set an authentication duration, and turn on "Apply global MFA
  settings by default" (or set the admin application's or policy's MFA to
  custom, security key only); then enrol the key at
  `<team>.cloudflareaccess.com/AddMfaDevice` and enrol a second, spare key. This
  is Cloudflare's feature of 2026 and is described from its documentation (MFA
  requirements; Independent MFA), not from a run; whether the pinned provider
  (5.27.0) can manage it is not established, so it is a dashboard step. Test it
  with the operator signed out before relying on it, and keep the spare key
  elsewhere: losing every enrolled key locks the operator out of the console.
  Sign in with Apple is not a built-in identity provider, would need the generic
  OIDC connector (an Apple client secret is a signed token that expires), and
  can assert a private-relay address instead of the real one that the policy
  matches; it is not recommended.
- **One origin.** The console shares an origin (`https://keyquorum.dev`) with
  the relay and, later, the customer app. Access's session cookie is scoped to
  the host, not the path, so the browser sends it to every path of the host: the
  relay Workers and a customer app would receive the operator's Access cookie
  (it is `HttpOnly`, so a script cannot read it, but a server on that origin
  can), and a script flaw in anything else served from `keyquorum.dev` runs on
  the same origin as the console and could call its API as the signed-in
  operator, though a change still needs the operator lock and cannot be made
  without it. The staging and production consoles and relays share the origin
  too. The admin Worker's own checks (the Access token, the lock, same-origin
  `Origin`) still apply, and the relay Workers ignore cookies; but the isolation
  of a hostname of its own is given up. If the customer app is built, a
  hostname of its own for the console (set `path` to a `/relay/<name>` on a
  different hostname, or return to a custom domain) restores it.
- The admin routes and Access applications are created only when
  `admin_environments` is set. No route bypasses Access: the path sits
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
