# catalog

What can be audited, why, and with which permission sets. Reads nothing, needs
no credentials, makes no request. Start here.

```bash
mlab-scw catalog                              # the whole surface, as a table
mlab-scw catalog rdb                          # one product, in prose
mlab-scw catalog --checks                     # every check, worst first
mlab-scw catalog --checks --severity critical
mlab-scw catalog --permissions                # the policy to attach
mlab-scw catalog -o json                      # the same, for a pipeline
```

## Why it exists as data

`src/scw/catalog.rs` holds one entry per Scaleway product API, one per resource
worth reading inside it, and one per finding that response supports. Keeping the
plan as data rather than as code buys three things:

1. **The plan can be read before it runs.** `catalog` on a laptop with no
   credentials tells you exactly which endpoints a sweep will touch. That is the
   difference between a tool you can point at production and one you have to
   read the source of first.
2. **The policy is generated, not guessed.** `--permissions` prints the
   deduplicated read-only permission sets the catalogue needs and nothing else —
   least privilege derived from intent rather than from trial and error against
   403s.
3. **Adding a product is a table entry.** Scaleway ships APIs faster than any
   audit tool tracks them; keeping up should cost a paragraph, not a module.

## The whole surface

```
$ mlab-scw catalog

  Audit surface

  PRODUCT              RESOURCE              SCOPE   PERMISSION SET               PATH
  IAM                  users                 global  IAMReadOnly                  /iam/v1alpha1/users
  IAM                  api-keys              global  IAMReadOnly                  /iam/v1alpha1/api-keys
  …
  Instances            servers               zone    InstancesReadOnly            /instance/v1/zones/{zone}/servers
  Instances            security-groups       zone    InstancesReadOnly            /instance/v1/zones/{zone}/security_groups
  …

  99 resources
```

## One product

```
$ mlab-scw catalog rdb

  Managed Database

  PostgreSQL and MySQL. The exposure is the endpoint list; the control is the
  ACL list; both are readable.

  base            /rdb/v1
  scope           region
  permission set  RelationalDatabasesReadOnly

  instances  /rdb/v1/regions/{region}/instances
  Engine version, high availability, backup schedule, encryption and
  endpoints.

  acls  /rdb/v1/regions/{region}/instances/{id}/acls
  Which source prefixes may connect.

  users  /rdb/v1/regions/{region}/instances/{id}/users
  Database roles and which are administrative.

  snapshots  /rdb/v1/regions/{region}/snapshots
  Database snapshots and their age.
```

Every path there is copy-pasteable into [`api`](Api).

## The checks

```
$ mlab-scw catalog --checks --severity critical

  Checks

  CRITICAL
  apple-silicon.servers.sudo-password
  sudo_password returned by a read call: AppleSiliconReadOnly is
  administrative access to the machine, whatever the name says
  …
```

`--severity` is a floor, not a filter: `--severity high` shows critical **and**
high. Check ids are `product.resource.slug` and are stable, which is what a mute
list will key on when there is one.

| level | means |
| --- | --- |
| `critical` | data or credentials are reachable from the internet right now |
| `high` | a control that should exist does not, and the exposure is direct |
| `medium` | a weakness that needs a second condition to be exploited |
| `low` | hygiene: it becomes one of the above if left alone |
| `info` | inventory, printed because an auditor asked, not because it is wrong |

## The policy

```
$ mlab-scw catalog --permissions

  Read-only permission sets this catalogue needs

  AppleSiliconReadOnly
  AuditTrailReadOnly
  BillingReadOnly
  …
  WebHostingReadOnly

  35 permission sets. Attach them to an application of its own, scoped to the
  projects you mean to audit — not to your user, and not at organization scope
  unless the account really is one project.
```

Drop the ones for products the account does not use. Three of them are worth
dropping on principle unless you need them, because they return live
credentials: `AppleSiliconReadOnly`, `ElasticMetalReadOnly`,
`DomainsDNSReadOnly`. See [Secrets](Secrets).

## JSON

`catalog -o json` is the machine-readable form, and is what the published
audit-surface page is generated from, so the page and the tool cannot disagree.

```bash
mlab-scw catalog -o json | jq -r '.[] | .path'
mlab-scw catalog -o json | jq -r 'group_by(.permission)[] | "\(.[0].permission)\t\(length)"'
mlab-scw catalog --checks -o json | jq '[.[] | select(.severity=="critical")] | length'
```

Each resource row carries:

| field | meaning |
| --- | --- |
| `product`, `productKey`, `base`, `scope` | which API, where it lives |
| `permission` | the read-only permission set that opens it |
| `path` | full path, with `{region}` / `{zone}` still in it |
| `needs` | a query parameter only the caller can fill, by name: `organization_id`, `project_id`, `policy_id`, `audience_id` |
| `paging` | `page`, `per_page`, `page_token`, or `none` for a singleton GET |
| `parent` | the resource whose ids this one is enumerated over |
| `checks` | how many findings it supports |

## `needs` is a name, not a category

It started as an enum with three variants. Then a real call to
`/iam/v1alpha1/rules` came back demanding `policy_id`, and `/iam/v1alpha1/jwts`
demanding `audience_id` — neither of which the Go SDK marks as required. A name
costs nothing to extend and cannot be wrong in a new way.

```bash
mlab-scw catalog -o json | jq -r '.[] | select(.needs != "") | "\(.needs)\t\(.path)"'
```

## Invariants

Three are tested rather than documented, because a catalogue that drifts is
worse than none: every check id starts with the product and resource it belongs
to, every `parent` resolves to a resource that exists, and any path containing
`{id}` has a parent to fill it.
