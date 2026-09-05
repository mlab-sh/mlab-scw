# api

A raw GET against any path, for everything the catalogue does not wrap yet.

```bash
mlab-scw api /iam/v1alpha1/users --list -Q organization_id=aaaaaaaa-1111-2222-3333-444444444444
mlab-scw api '/instance/v1/zones/{zone}/servers' --list --zone fr-par-1 --per-page
mlab-scw api '/k8s/v1/regions/{region}/clusters' --list --region fr-par
mlab-scw api /account/v3/projects --list -Q organization_id={org}
```

## GET only

There is no flag that sends anything else, and there will not be one. A tool
that can be talked into a POST is no longer a tool you can point at production
without reading its source first.

## Query parameters

`-Q key=value`, repeatable. Uppercase on purpose: `-q` is `--quiet` everywhere
else in this CLI, and a short flag that means one thing globally and another
inside one subcommand is a trap, not a convenience.

```bash
mlab-scw api /iam/v1alpha1/logs --list -Q organization_id={org} -Q order_by=created_at_desc
```

Values go through the same placeholder expansion as the path.

## Placeholders

A path or a query value may contain:

| placeholder | filled from |
| --- | --- |
| `{region}` | `--region`, or the region of `--zone` |
| `{zone}` | `--zone` |
| `{org}` | `--organization-id`, or the profile |
| `{project}` | `--project-id` |

`{region}` and `{zone}` deliberately refuse to guess. If the profile covers more
than one, the command errors:

```
  ✖ {zone} needs --zone; this profile covers 10
```

Silently picking `fr-par-1` would report a clean zone and call it a clean
account.

Every path in `mlab-scw catalog` is written with these placeholders already in
it, so the two commands compose:

```bash
mlab-scw catalog registry            # find the path
mlab-scw api '/registry/v1/regions/{region}/namespaces' --list --region fr-par
```

## Lists

```
$ mlab-scw api '/registry/v1/regions/{region}/namespaces' --list --region fr-par

  NAME              ID                                    STATUS  REGION  IS_PUBLIC  CREATED_AT              ENDPOINT
  build-cache       11111111-2222-3333-4444-555555555501  ready   fr-par  false      2025-04-02  (17mo ago)  rg.fr-par.scw.cloud/build-cache
  platform          11111111-2222-3333-4444-555555555502  ready   fr-par  false      2025-04-03  (17mo ago)  rg.fr-par.scw.cloud/platform
  fn-artifacts      11111111-2222-3333-4444-555555555503  ready   fr-par  false      2025-06-24  (14mo ago)  rg.fr-par.scw.cloud/fn-artifacts
  scratch           11111111-2222-3333-4444-555555555504  ready   fr-par  true       2025-12-10  (8mo ago)   rg.fr-par.scw.cloud/scratch

  4 items
```

The columns are picked from the first row, and the order is not alphabetical.
Identity first, then **booleans**, then everything else, with `project_id` and
`organization_id` deliberately last. In this API a boolean is almost always a
control — `is_public`, `protected`, `disable_auth`, `allow_insecure` — so when
eight columns have to stand in for forty fields, the switches are the ones worth
the space. Two 36-character UUIDs nobody reads would otherwise crowd them off
the table entirely.


`--list` walks every page and prints the collection as a table.

| flag | when |
| --- | --- |
| `--list` | the endpoint returns a collection |
| `--limit N` | one page of N instead of everything |
| `--collection FIELD` | the body field holding the items, when guessing is wrong |
| `--per-page` | Instances, which pages with `per_page` rather than `page_size` |
| `--token-paging` | Audit Trail, which pages with `page_token` |

Without `--collection`, the items are found by shape: a Scaleway list body has
exactly one array in it. The `paging` and `collection` columns of
`catalog -o json` say which flags a given resource needs.

## Secrets are masked

Several read endpoints return live credentials — an Apple silicon
`sudo_password`, a BMC login, a managed certificate's `private_key`. They are
replaced by their length, and the count is reported:

```
$ mlab-scw api '/apple-silicon/v1alpha1/zones/{zone}/servers' --list --zone fr-par-1

  ! 2 secret value(s) in this response were replaced by their length;
    --unsafe-values prints them
```

A length is not a secret and is what a strength check needs. `--unsafe-values`
prints the real thing, and is named for what it does to your terminal
scrollback, your ticket system and your screen recording. See [Secrets](Secrets).

## Single objects

Without `--list`, the response is rendered as a key/value block:

```
$ mlab-scw api /iam/v1alpha1/api-keys/SCWEXAMPLEACCESSKEY0

  access_key          SCWEXAMPLEACCESSKEY0
  application_id      eeeeeeee-1111-2222-3333-444444444444
  created_at          2026-02-11T09:41:07Z  (7mo ago)
  creation_ip         203.0.113.24
  default_project_id  bbbbbbbb-1111-2222-3333-444444444444
  deletable           true
  description         mlab-scw audit
  editable            true
  expires_at          2027-02-11T09:41:07Z
  managed             false
```

## With jq

`-o json` prints exactly what the API returned, untouched apart from the secret
masking:

```bash
mlab-scw api '/instance/v1/zones/{zone}/security_groups' --list --zone fr-par-1 -o json \
  | jq -r '.[] | select(.inbound_default_policy == "accept") | .name'
```
