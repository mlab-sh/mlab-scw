# quiet

The products nobody looks at.

```bash
mlab-scw quiet
mlab-scw quiet --severity critical
mlab-scw quiet -o json | jq '.findings'
```

Alias: `forgotten`.

## Why a command for this

Nothing in an account's daily operation surfaces any of it. A registry
namespace's visibility, a credential pasted into an environment variable, a DNS
record pointing at an address released last year, a device fleet configured to
trust anything that connects, a Mac runner nobody remembers renting — none of it
appears on a dashboard, none of it pages anybody, and all of it stays true for
years.

Which is why it is where the surprising findings are. [`iam`](Iam) tells you who
can act; [`exposure`](Exposure) tells you what answers. This tells you what has
been sitting there.

## The report

```
$ mlab-scw quiet

  The quiet products

  calls     189
  projects  4
  findings  3

  ! this report is partial; these were not readable
    mnq/sns-credentials: not activated in 8 localities
    mnq/sqs-credentials: not activated in 8 localities

  Findings

  CRITICAL

  jobs.job-definitions.plaintext-secret
  2 credential(s) in environment_variables rather than
  secret_environment_variables, so a read-only key receives them:
  S3_ACCESS_KEY (a Scaleway access key); S3_SECRET_KEY (the name says
  credential and the value is 40 opaque characters)
    batch-runner (fr-par)

  LOW

  registry.namespaces.empty  ×2
  no images, and a name nobody will remember reserving
    build-cache (fr-par)
    fn-artifacts (fr-par)

  1 critical  ·  2 low
```

Around 190 calls in three seconds: 30 resources over every locality, then one
call per DNS zone found.

**Project-scoped products get their own fan-out.** Messaging & Queuing refuses a
call without a `project_id`, so the sweep reads the project list first and asks
once per project. Without that list those products are silently unaudited, and
the header says `projects: unknown` rather than pretending otherwise.

## The credential detector

The highest-value check in the catalogue, and the easiest to get wrong. A
detector that flags `LOG_LEVEL=debug` is switched off within a day; one that
misses `DATABASE_URL=postgres://user:hunter2@db/app` was not worth writing.

It answers on two independent grounds and says which:

| ground | example | confidence |
| --- | --- | --- |
| the **value** is shaped like a known credential | a PEM block, a JWT, an AWS or Scaleway or GitHub or Slack key, a URL with a password in it | certain — nothing else looks like these |
| the **name** says credential *and* the value could be one | `API_TOKEN=x7f2k9dl2mzq0war` | a guess, marked as one |

And it deliberately stays quiet on the four that make a naive detector unusable:

```
TOKEN_TTL=3600                  a name that says secret, a value that cannot be
SECRET_NAME=database-password   the name of a secret, not a secret
API_KEY_FILE=/run/secrets/key   a path
DB_PASSWORD=${DB_PASSWORD}      a reference, which is the correct pattern
```

**A finding never carries the value.** It names the variable and the reason,
because an audit report is copied into tickets and terminals, and a leak
detector that leaks is worse than none.

It reads `environment_variables`, never `secret_environment_variables` — the
second is masked by the API, the first is returned in full to anything holding
the read-only permission set. That asymmetry is the whole point of the check.

## Dangling names

A DNS record pointing at Scaleway infrastructure this account does not hold is a
name somebody else can claim, and the first step of a convincing phish. The
check builds the set of addresses and platform hostnames the account currently
holds — Instance and Flexible and load-balancer addresses, IPAM, container and
function domains, registry endpoints, cluster URLs — and compares every A, AAAA
and CNAME against it.

**Only hostnames Scaleway serves are judged.** An arbitrary IPv4 cannot be
attributed to a provider from this API, so a record pointing at another host is
left alone rather than guessed at. That is a deliberate false-negative: the
alternative turns every third-party CNAME into a takeover alert.

## What else it looks at

| area | the finding that matters most |
| --- | --- |
| Serverless | a credential in a plain environment variable, on a container, function, job or the namespace they inherit from |
| Registry | an image marked public inside a private namespace |
| Domains | a record pointing at infrastructure you no longer hold; SPF ending in `?all`; DMARC of `none` or absent; no CAA; expiry inside 30 days with auto-renew off; DNSSEC off |
| Managed certificates | that the listing returns `private_key` at all — `DomainsDNSReadOnly` is the ability to impersonate the sites it covers |
| IoT | auto-provisioning, devices that may skip TLS, one identity shared across connections, routes forwarding off-platform |
| Apple silicon | that the listing returned the machine's sudo password; runners idle for a month and billed by the day |
| Secret Manager | one version created over a year ago; unprotected; referenced by nothing; under the platform key rather than yours |
| Key Manager | no rotation policy; unprotected; never rotated |
| Messaging | a credential with `can_manage` where consuming would do |
| Transactional Email | a sending domain whose records do not check out; a bad reputation, which is what a compromised sending key looks like from outside |
| Leftovers | public or year-old custom images; detached volumes; snapshots older than any stated policy; filesystems mounted by nothing |

## One listing that is not yours

`GET /instance/v1/zones/{zone}/images` returns **Scaleway's entire marketplace**
alongside your own images: some twenty-three thousand of them, every one marked
`public`. Judged naively that produces a report which is 99.99% AlmaLinux.

So the sweep filters by organization at the API — which also turns a
twelve-second call into a one-second one — *and* the check refuses to judge an
image it cannot attribute to the account. With no organization to compare
against it reports nothing at all, because judging somebody else's resources is
worse than judging none.

## Permissions

Sixteen read-only permission sets. Whatever is missing becomes a gap line rather
than an error, deduplicated per product — see [Exposure](Exposure#coverage) for
how silences are reported.

`SecretManagerReadOnly` is metadata only by design, and that is all this command
wants: it counts and dates secrets, and never reads one.
