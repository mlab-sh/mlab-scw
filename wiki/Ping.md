# ping

Check that the current profile reaches the API, and report which permission sets
actually answered.

```bash
mlab-scw ping
mlab-scw ping --profile prod
mlab-scw ping -o json
```

## Why it is a ladder and not a single call

A Scaleway key has no universal "who am I" endpoint. Every path sits behind a
permission set, so a key can be perfectly valid and still be refused by the
first thing tried. Reporting "unreachable" there would be a lie.

So `ping` probes a short ladder and reports each rung, because *that* is the
useful answer: a refusal from IAM and a 200 from Account is a working key with a
narrow policy, not a broken one.

It starts at IAM, and not for tidiness: `/account/v3/projects` requires an
`organization_id`, and the only way to learn one from a bare key is through IAM.
A profile that already recorded one skips that hop.

## Output

```
$ mlab-scw ping

  ✔ answered in 412ms

  profile       prod
  endpoint      https://api.scaleway.com
  access key    SCWEXAMPLEACCESSKEY0
  organization  aaaaaaaa-1111-2222-3333-444444444444

  Probes

  PROBE    STATUS  PERMISSION SET
  iam      ok      IAMReadOnly
  account  ok      ProjectReadOnly
```

`DETAIL` is absent because nothing had anything to say. Columns that carry no
data on this account are dropped, so a table's width tells you something rather
than being padded with empties.

A key with no IAM permission set, which is a normal thing for an audit key to
be:

```
  PROBE    STATUS  PERMISSION SET   DETAIL
  iam      denied  IAMReadOnly      API error 403 [permissions_denied]: insufficient permissions
  account  ok      ProjectReadOnly
```

## Statuses

| status | means |
| --- | --- |
| `ok` | the endpoint answered |
| `denied` | 403: the credentials are good, this permission set is missing |
| `failed` | anything else — a 401 is a wrong key, everything else is a network or service problem |
| `skipped` | the probe could not be attempted; the detail says what is missing |

The command exits non-zero only when **nothing** reached the API. A `denied`
still proves the credentials authenticate, so it counts as reached.

## JSON

```bash
mlab-scw ping -o json | jq '.probes[] | select(.status != "ok")'
```

```json
{
  "profile": "prod",
  "endpoint": "https://api.scaleway.com",
  "accessKey": "SCWEXAMPLEACCESSKEY0",
  "organizationId": "aaaaaaaa-1111-2222-3333-444444444444",
  "reached": true,
  "probes": [
    {"probe": "iam", "status": "ok", "grants": "IAMReadOnly"},
    {"probe": "account", "status": "ok", "grants": "ProjectReadOnly"}
  ],
  "elapsed": "412ms"
}
```
