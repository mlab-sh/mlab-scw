# whoami

What this API key is, and everything it is allowed to do.

```bash
mlab-scw whoami
mlab-scw whoami -o json
```

Alias: `identity`.

## Why this is the most important command here

A finding that says "no public databases" is worth exactly as much as the key's
reach. If the policy covers two projects out of nine, the sweep saw two projects
out of nine and the clean report is meaningless.

`whoami` is what makes the rest of the output honest. It resolves the grant the
long way rather than trusting what the profile says about itself:

```
api key  →  principal  →  groups  →  policies  →  rules  →  permission sets + scopes
```

The group hop matters: a grant arriving through group membership is the one
people forget they made.

## Output

An audit key, which is what this tool is for — an application, scoped by policy:

```
$ mlab-scw whoami

  Identity

  access key              SCWEXAMPLEACCESSKEY0
  principal               mlab-scw-audit (application)
  organization            aaaaaaaa-1111-2222-3333-444444444444
  role                    application
  created                 2026-02-11T09:41:07.221904Z  (7mo ago)
  created from            203.0.113.24
  expires                 2027-02-11T09:41:07.221Z  (in 5mo)
  object storage project  bbbbbbbb-1111-2222-3333-444444444444

  Grants

  POLICY               PERMISSION SET               SCOPE     ON
  mlab-scw-audit-ro    IAMReadOnly                  projects  2 project(s)
  mlab-scw-audit-ro    InstancesReadOnly            projects  2 project(s)
  mlab-scw-audit-ro    RelationalDatabasesReadOnly  projects  2 project(s)
  mlab-scw-audit-ro    VPCReadOnly                  projects  2 project(s)

  4 grants
```

Every date carries its distance from now, in both directions: an API key's age
is a finding, and so is how long is left before it expires.

## The owner is a special case, and it looks like the opposite of one

A key belonging to the Organization Owner produces an **empty** grant table.
That reads like a permissions problem and is the reverse:

```
$ mlab-scw whoami

  Identity

  access key              SCWEXAMPLEACCESSKEY0
  principal               ops@example.com (user)
  organization            aaaaaaaa-1111-2222-3333-444444444444
  role                    organization owner
  two-factor              enabled
  last login              2026-09-05T20:39:49.051239Z  (48m ago)
  created                 2026-09-05T20:57:42.857076Z  (30m ago)
  created from            203.0.113.24
  expires                 2026-09-12T20:57:42.663Z  (in 6d)
  object storage project  aaaaaaaa-1111-2222-3333-444444444444

  ! this is the Organization Owner. It holds every permission on every product
    in every project, implicitly — no policy grants that and no policy can take
    it away, so the grant table below is not the limit of what this key can do

  Grants

  none — and none is needed. The owner is above the policy system, not outside it.
```

The owner sits above IAM rather than inside it: there is no policy to read
because there is no policy involved. An audit run with an owner key sees
everything, which makes its coverage complete and its own blast radius total —
both worth stating in the report.

Notice the last line of the identity block: the **Object Storage project is the
organization's own UUID**. That is not a bug. On Scaleway the `default` project
shares the organization's identifier, so a key that has never been given a
preferred project points at `default`.

## The warnings

| warning | means |
| --- | --- |
| `no expiry date` | the key outlives the reason it was made. `max_api_key_expiration_duration` in **IAM → Settings** makes creating one impossible. |
| `Organization Owner` | above the policy system. The grant table is not the limit of what this key can do. |
| `belongs to a person` | the key's permissions are a moving target that changes whenever somebody adjusts that person's access. An audit key belongs to an application. |
| `no second factor` | the principal is a human without MFA, and this key is theirs. On an owner, that single control stands between a password and the whole organization. |

## When it can say less

Reading policies needs an IAM permission set. Without one:

```
  ! the organization could not be resolved, so no policy can be listed; pass
    --organization-id, or run `mlab-scw login` to record it

  Grants

  no policy readable; either the key holds no IAM permission set, or it truly has none
```

That is an honest answer rather than an empty one — and it is itself worth
knowing, because it means nothing else this tool prints can state its own
boundary.

## JSON

```bash
mlab-scw whoami -o json | jq -r '.grants[].permissionSet' | sort -u
mlab-scw whoami -o json | jq -r 'select(.expiresAt == "never") | .accessKey'
mlab-scw whoami -o json | jq 'select(.owner) | "this key is the organization owner"'
mlab-scw whoami -o json | jq 'select(.twoFactor == false) | "human principal without MFA"'
```
