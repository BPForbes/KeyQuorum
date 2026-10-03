# Security policy

KeyQuorum handles key material, hardware tokens and encrypted files, so security
reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately. Do not open a public issue or pull request for a
vulnerability.

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**. Include what you found, how to
reproduce it, and which version or commit you tested.

Do not attach private keys, API keys or bearers, `.kqpb` envelopes, `*.kqcert`,
`*.kqrl` or `*.kqpolicy` files, `device.skey`, or a relay database. A
description or a minimal reproduction with throwaway test keys is enough.

## What to expect

These are goals, not guarantees:

- an acknowledgement within 5 business days;
- an initial assessment within 10 business days;
- a fix or mitigation plan, and credit if you want it, once the issue is
  confirmed. Please keep the details private until a fix is available.

## Scope

In scope: the `keyquorum` and `keyquorum-device` command-line tools, the
mailbox relay and its protocol, the sealed-envelope and file formats, quorum,
custody and approval logic, and the KeyQuorum Lab.

Out of scope: findings that need a compromised device or operating system, social
engineering, denial of service by volume alone, and the public demo passphrases
and seeded data in the Lab, which are published on purpose and protect nothing.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x (latest `main`) | yes |

## Automated checks

The `security` workflow runs RustSec advisories (`cargo audit`), `cargo deny`
(advisories, licenses, sources), secret scanning (`gitleaks`), `npm audit` for the
Lab and CodeQL for its TypeScript. Dependabot proposes dependency updates.
