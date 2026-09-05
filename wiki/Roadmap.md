# Roadmap

## Phase 1 — the base (built)

Everything needed to talk to an account safely, and to know what talking to it
would cover.

- **The key manager.** Profiles in `~/.mlab/scw.conf`, 0600 in a 0700 directory,
  both halves of the pair shape-checked before a request is spent, secret read
  without echo, `SCW_*` environment compatibility. [Configuration](Configuration)
- **The HTTP layer.** One GET path, three paging styles, bounded retries on 429
  and 5xx honouring `Retry-After`, redirects refused so the token cannot leak,
  typed errors that tell a refused permission apart from a broken key and fold
  the API's `details` array into the message. [Surfaces](Surfaces)
- **Localities.** Every region and zone swept by default; `--region` and
  `--zone` narrow coherently across global, regional and zonal products.
- **The catalogue.** 36 product APIs, 99 resources, 221 checks, as data rather
  than code — so the plan prints before it runs and the least-privilege policy
  is generated from intent. [Catalog](Catalog)
- **Identity.** The organization bootstrap — key, principal, organization —
  shared by every command that needs it. [Surfaces](Surfaces#3-there-is-no-who-am-i-and-the-bootstrap-is-awkward)
- **Commands.** [catalog](Catalog), [login](Login), [ping](Ping),
  [whoami](Whoami), [project](Project), [api](Api), [profile](Profile),
  [config](Config), [completions](Completions).
- **Secret redaction** on every printed response. [Secrets](Secrets)

## Phase 2 — reading the account

- **[`iam`](Iam)** — *built.* Who can do what, and twenty-six graded checks on
  it. The checks are pure functions over fetched JSON in `src/audit/iam.rs`,
  tested against fixtures, so a later `sweep` can feed them from a file instead
  of from the API. The report groups by check, names what it could not read, and
  names the catalogued checks it does not yet derive.
- **`sweep`** — walk the catalogue and write one dated, secret-free record of
  everything the key can see. [`api`](Api) already proves each path individually;
  this is the fan-out over projects, regions and zones, with per-endpoint
  refusals recorded rather than fatal, and concurrency that respects the rate
  limiter the client already backs off from.
- **`audit`** — the checks in `catalog --checks`, as pure functions over a
  sweep. Graded, worst first, each finding carrying the endpoint it came from.
- **`diff`** — what changed between two sweeps. The most useful thing the UniFi
  tool does, and it transfers directly.

## Phase 3 — the questions no single endpoint answers

These are why reading thirty-six APIs in one pass is worth the effort.

- **`exposure`** — IPAM plus per-product addresses plus load-balancer frontends
  plus managed-database endpoints plus serverless privacy flags plus PAT rules,
  resolved into one list of what answers from the internet and what it is.
- **`takeover`** — DNS records whose targets the account no longer holds. Needs
  the address inventory `exposure` builds.
- **`blast`** — what one credential reaches: policies and rules on one side,
  private NICs, gateway networks and VPC ACL rules on the other.
- **`spend`** — billing read as a detector. A consumption line moving against
  its own twelve-month baseline is the earliest signal of a stolen key that most
  accounts actually have.

## Phase 4 — the surface that is not on this API

- **Object Storage.** S3 over SigV4 at `s3.{region}.scw.cloud` with the same key
  pair: bucket ACLs, bucket policies, public access, lifecycle, versioning.
  Requires signing code, and is scoped to the key's *preferred Object Storage
  project* — which has to be said out loud in the output, because a public
  bucket in another project is invisible to the same credential that can list
  every server in it.
- **Packaging.** Homebrew, `.deb`, `.rpm`, prebuilt binaries, a release
  pipeline — as `mlab-unifi` has.
