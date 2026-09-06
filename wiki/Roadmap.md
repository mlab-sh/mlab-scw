# Roadmap

## Where it stands

**113 of the catalogue's 229 checks are derived** — 49%. The rest is not
oversight, it is work not done, and every report says which is which rather than
letting silence read as safety.

| command | checks | what it answers |
| --- | --- | --- |
| [`iam`](Iam) | 26 | who can do what |
| [`exposure`](Exposure) | 34 | what answers from the internet, and what narrows it |
| [`quiet`](Quiet) | 47 | what nobody has looked at in years |
| [`advisories`](Advisories) | 6 | what has been published about what it runs |

Three catalogued **criticals** are still underived, and they are named below
rather than buried.

## Built

**Phase 1 — the base.** The key manager (profiles in `~/.mlab/scw.conf`, 0600 in
a 0700 directory, both halves of the pair shape-checked before a request is
spent, `SCW_*` compatibility). The HTTP layer: one GET path, three paging
styles, bounded retries on 429 and the retryable 5xx, redirects refused so the
token cannot leak, typed errors that tell a refused permission apart from a
broken key and fold the API's `details` array into the message. Localities swept
in full by default. The [catalogue](Catalog) as data. The organization bootstrap
in `scw/identity.rs`. `catalog`, `login`, `ping`, `whoami`, `project`, `api`,
`profile`, `config`, `completions`. Secret redaction on every printed response.

**Phase 2 — [`iam`](Iam).** Principals, credentials, policies, rules, groups,
SSH keys and the organization's own security settings, as pure functions over
fetched JSON in `src/audit/iam.rs`.

**Phase 3 — [`exposure`](Exposure).** The cross-product map of what answers from
the internet and what narrows it, in three rounds over every locality. The
concurrent fan-out it needed (`src/scw/sweep.rs`) is the machinery the rest
reuses.

**Phase 4 — [`quiet`](Quiet).** Plaintext credentials in environment variables,
DNS records pointing at infrastructure the account no longer holds, registry
visibility, device-fleet trust, forgotten data. Rests on the credential detector
in `src/audit/credential.rs`.

**Phase 5 — [`advisories`](Advisories).** Versions matched against the published
corpus by CPE and version range. The only command that talks to anything but
`api.scaleway.com`: opt-in per run, a product identifier is all that leaves, and
`--explain` prints the payload before it is sent.

**Packaging.** Homebrew, `.deb`, `.rpm`, prebuilt tarballs for macOS and Linux on
x86_64 and arm64, checksums, and a release pipeline. See [Releasing](Releasing).

## What is missing, worst first

### 1. Detection — can this account notice anything?

The one gap that changes the value of everything already built. The same
misconfiguration is a different risk in an account that would spot it within the
hour and one that would never spot it at all, and right now the tool says
nothing about which of those this is.

- **Cockpit**: is alerting switched on, does it have anywhere to send an alert,
  and is log retention longer than the time it takes to notice a breach. Every
  call is project-scoped, so the honest answer is per project and is usually
  worse than the account-level one.
- **Audit Trail**: how far back the record actually goes, which bounds every
  answer this tool gives; IAM changes, which are the shortest path from a
  foothold to persistence; and
  `audit-trail.authentication-events.success-after-failures` — **a catalogued
  critical**: a successful login after a run of failures, from a country the
  account has never seen.
- **Billing read as a detector**: a consumption line moving against its own
  twelve-month baseline is the earliest signal of a stolen key that most
  accounts actually have. Mining shows up as compute, exfiltration as Object
  Storage egress, and both arrive weeks before anyone reads a log.

### 2. `instance.user-data.secret` — a catalogued critical

cloud-init is the most reliable place to find a plaintext credential in any
cloud account. The detector that would read it already exists and is tested
(`src/audit/credential.rs`, phase 4); what is missing is one more sweep round,
per server, over `/servers/{id}/user_data`. Nothing to design, only to build.

### 3. `diff` — run it twice, compare

The tool can audit and cannot compare. Every run starts from nothing, so a
bucket that became public on Tuesday looks exactly like one that has always been
public. This is what `mlab-unifi` does best and it transfers directly: one dated
record per run, then what changed between two of them. It needs `sweep` below.

### 4. Object Storage

The documented blind spot, and a real one. Buckets, ACLs, bucket policies,
public-access settings, lifecycle and versioning are S3 over SigV4 at
`s3.{region}.scw.cloud`, not on `api.scaleway.com`. Two consequences: it needs
request signing rather than a header, and an API key carries a *preferred
Object Storage project* fixed at creation — so a public bucket in another
project is invisible to the same credential that can list every server in it.
That has to be said in the output, not just implemented.

### 5. `sweep` and `audit`

Four commands each sweep for themselves, which duplicates calls and means "run
everything" is four invocations and four reports. One sweep writing a dated,
secret-free record, and one `audit` reading it, would fix both — and would let
the existing pure check functions run against a file instead of an account,
which is what makes `diff` possible.

### 6. `baremetal.bmc.open` — a catalogued critical, deferred on purpose

`GET /servers/{id}/bmc-access` returns a URL, a login and a password in plain
text. Reading it to confirm the console is exposed is also *making it leave the
API*. It is one round to implement and a decision to take first, so it is
recorded here rather than shipped quietly.

### 7. Smaller, known

- `--project-id` fills `{project}` in [`api`](Api) and nothing else reads it.
- The optional `mlab.sh` key: the service advertises no authentication scheme,
  so the header name has to come from somebody who knows it before the profile
  gains a field for it.
- 40 catalogued `high` checks remain, mostly configuration rather than
  reachability: backup schedules, engine end-of-life, LB backend TLS
  verification, VPC ACL defaults, Edge Services WAF mode.
