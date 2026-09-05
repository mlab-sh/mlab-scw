# Surfaces

How the Scaleway API is shaped, and the four ways that shape produces a wrong
answer if you ignore it.

## One host, one header, one path

Every product answers on `api.scaleway.com`, authenticated by the API key's
secret half in an `X-Auth-Token` header. What differs between products is only
the path, and the path is the whole design:

```
https://api.scaleway.com/instance/v1/zones/fr-par-1/servers
                        └ product └ ver └ locality └ resource
```

`mlab-scw catalog` prints the product, version, locality kind and resource path
of everything it knows how to read.

## 1. Three localities, not one

| kind | path segment | values |
| --- | --- | --- |
| global | *(none)* | IAM, Account, Domains, Billing, Edge Services |
| regional | `/regions/{region}` | `fr-par`, `nl-ams`, `pl-waw`, `it-mil` |
| zonal | `/zones/{zone}` | `fr-par-1..3`, `nl-ams-1..3`, `pl-waw-1..3`, `it-mil-1` |

This is the most common way a cloud audit produces a false negative. Sweep
`fr-par` only and the account reads clean while the public database sits in
`pl-waw-2`.

So **every sweep covers every locality by default**. `--region` narrows both
regional and zonal products; `--zone` narrows a zonal sweep to that zone *and* a
regional sweep to its parent region, so one flag always means one place.

```bash
mlab-scw api '/instance/v1/zones/{zone}/servers' --list --zone fr-par-1
```

`{region}` and `{zone}` deliberately refuse to guess: if the profile covers more
than one, the command errors rather than silently picking the first.

## 2. Versions are per product, and mostly not v1

`iam/v1alpha1`, `secret-manager/v1beta1`, `vpc/v2`, `vpc-gw/v2`,
`serverless-jobs/v1alpha2`, `apple-silicon/v1alpha1`, `audit-trail/v1alpha1`.
Roughly a third of the surface an audit depends on is alpha or beta, which means
field names move. Anything built on it should degrade rather than fail.

## 3. There is no "who am I", and the bootstrap is awkward

Every IAM listing requires an `organization_id`, and so does
`GET /account/v3/projects` — the natural first call of any audit, which without
one answers `400 invalid_arguments`.

But an API key object does not carry an organization.
`GET /iam/v1alpha1/api-keys/{access_key}` returns a **principal**: an
`application_id` or a `user_id`. The organization is one hop further out, on
that application's or user's own record.

```
api-keys/{access_key}  →  applications/{id}  →  organization_id
                          users/{id}
```

That hop needs an IAM read permission, so a valid key holding only, say,
`InstancesReadOnly` cannot discover which organization it is auditing and has to
be told. `login` walks the ladder, and falls back to asking. Once recorded in
the profile, neither hop is made again.

## 4. Three paging styles

| style | parameters | who |
| --- | --- | --- |
| page | `page`, `page_size`, `total_count` in the body | nearly everything |
| per-page | `page`, `per_page` | Instances, and its age shows |
| token | `page_size`, `page_token`, `next_page_token` | Audit Trail |

Getting this wrong does not error. It silently returns the first hundred of
something, and the report is quietly incomplete. `catalog -o json` records the
style per resource; `api --list` takes `--per-page` or `--token-paging` when you
are driving it by hand.

## Errors

Scaleway answers `{"type": "...", "message": "..."}`. For a rejected request it
adds a `details` array that the message itself ignores:

```json
{
  "type": "invalid_arguments",
  "message": "invalid argument(s)",
  "details": [
    {"argument_name": "organization_id", "reason": "required",
     "help_message": "cannot be empty"}
  ]
}
```

`invalid argument(s)` alone is unactionable, so the details are folded into the
message this tool shows:

```
API error 400 [invalid_arguments]: invalid argument(s): organization_id is required (cannot be empty)
```

Four statuses mean four different things, and the tool treats them differently:

| status | means | what happens |
| --- | --- | --- |
| 401 | the secret key is wrong | fatal; nothing is saved |
| 403 | good key, no permission set for this product | reported, sweep continues |
| 404 | good secret key, the access key names nothing | fatal in `login` |
| 412 | the product is not activated in that project | reported; it is an answer, not a failure |
| 429, 5xx | a queue, or a gateway | retried up to 3 times |

A retry honours `Retry-After` when the server sends one, capped at 20 seconds,
and otherwise doubles from one second. Nothing the *account* decides is ever
retried: a 403 is the same answer however many times you ask, and retrying one
across ten zones just makes an audit slow.

## Required parameters are not always where the SDK says

`scaleway-sdk-go` marks a required scoping parameter by making it a plain
`string` rather than a `*string`, which is a good first approximation and not the
whole truth. Three endpoints in this catalogue were declared as needing nothing
and were corrected only when a real call refused them:

| endpoint | actually requires |
| --- | --- |
| `/iam/v1alpha1/rules` | `policy_id` — it is enumerated per policy |
| `/iam/v1alpha1/jwts` | `audience_id` — the user whose sessions you want |
| `/mnq/v1beta1/regions/{region}/sqs-credentials` | `project_id` |

The catalogue records the parameter by name in its `needs` field, so `api` and
the sweep both know to supply it:

```bash
mlab-scw catalog -o json | jq -r '.[] | select(.needs != "") | "\(.needs)\t\(.path)"'
```

## Redirects are refused

The token rides in a default header, which an HTTP client would replay on a
cross-host redirect. The client follows none: a redirect is reported as an error
naming the target, rather than leaking the secret key to it.

## Not on this API at all

**Object Storage.** Buckets, ACLs, bucket policies, public-access settings and
lifecycle rules are S3 over SigV4 at `s3.{region}.scw.cloud`, signed with the
same access key and secret key. Two consequences: it needs signing code rather
than a header, and an API key carries a *preferred Project for Object Storage*
fixed at creation — so S3 calls only ever see that one project's buckets,
whatever the key's IAM policy says. It is on the [Roadmap](Roadmap).
