# iam

Who can do what, and what is wrong with it.

```bash
mlab-scw iam                          # every check, worst first
mlab-scw iam audit --severity high    # critical and high only
mlab-scw iam -o json | jq '.findings'

mlab-scw iam users
mlab-scw iam applications             # alias: apps
mlab-scw iam keys                     # alias: api-keys
mlab-scw iam policies
mlab-scw iam groups
mlab-scw iam ssh-keys                 # alias: ssh
mlab-scw iam settings
```

## Why this first

Every other finding this tool can produce is reachable by whoever holds the
wrong credential here. An open database matters because someone can reach it; a
key with no expiry and organization-wide scope is how they get to be someone.

It is also the cheapest report to run: eight global calls, no locality sweep,
and it bounds every later answer — a key that can only see two projects produces
a clean report about two projects.

## The report

```
$ mlab-scw iam

  IAM

  organization  aaaaaaaa-1111-2222-3333-444444444444
  users         1
  applications  4
  api keys      15
  policies      9
  groups        5
  ssh keys      1

  Findings

  CRITICAL

  iam.api-keys.never-expires  ×13
  no expiry date: the credential outlives the person, the project and the
  reason it was made
    Project - default (aaaaaaaa) · SCWEXAMPLEACCESSKEY0
    platform-deploy · SCWEXAMPLEACCESSKEY1
    ops@example.com · SCWEXAMPLEACCESSKEY2
    …

  iam.policies.all-products-full-access  ×4
  AllProductsFullAccess, scoped to projects — full control of every product in
  them
    Group - Administrators
    Group - Editors
    …

  HIGH

  iam.api-keys.stale  ×6
    platform-deploy · SCWEXAMPLEACCESSKEY1
      created 17mo ago, never rotated since
    ops@example.com · SCWEXAMPLEACCESSKEY2
      created 18mo ago, never rotated since
    …

  18 critical  ·  21 high  ·  10 medium  ·  7 low  ·  1 info

  3 catalogued IAM check(s) are not derived yet: iam.logs.grant-outside-hours,
  iam.logs.coverage, iam.jwts.foreign-ip
```

Three things about that shape are deliberate.

**One check firing thirteen times is one finding about thirteen keys.** The
explanation is a property of the check, so it is printed once and the subjects
listed under it. Repeating a two-line paragraph under each subject buries every
other check beneath a wall of identical prose, which is exactly how audit output
stops being read.

**Unless the reason differs.** When each subject earned the finding for its own
reason — `created 17mo ago` versus `created 18mo ago` — the difference *is* the
evidence, so it stays attached to the subject.

**The report says what it did not check.** Two ways: a catalogued check with no
implementation behind it is named at the bottom, and anything the key could not
read is named at the top:

```
  ! this report is partial; what follows describes only what could be read
    ssh-keys: no permission set for it
    security-settings: no permission set for it
```

A finding list is worth exactly its coverage. Hiding a permission error would
turn "I could not look" into "there was nothing there".

## What it checks

`mlab-scw catalog iam --checks` prints the specification; the report prints what
was found. Twenty-six checks across eight resources:

| resource | looks for |
| --- | --- |
| **users** | no second factor; the owner used as a daily driver; dormant or never-used accounts; locked accounts still carrying policies |
| **applications** | no API key, so the policies on it are attached to nothing; no description |
| **api-keys** | no expiry; never rotated in a year; bound to a person rather than an application; an Object Storage project fixed to `default`; the addresses keys were created from |
| **policies** | no principal; `AllProductsFullAccess`; organization scope where a project list would do; a principal that cannot use it |
| **rules** | a write permission set inside a policy named for reading; organization-wide rules with no condition |
| **groups** | a group that means *everyone*; an empty group carrying policies; people and machines mixed |
| **ssh-keys** | RSA under 3072 bits or DSA, read out of the key's own wire format; keys older than two years; keys disabled but not deleted |
| **security-settings** | no maximum key lifetime; console sessions longer than a working day; no lockout after failed logins |

Two of them are worth explaining because they look like the opposite of what
they are.

**`iam.groups.everyone`.** A Scaleway group can be defined as `all_users` or
`all_applications` rather than by a membership list. In a listing it shows zero
members, exactly like a forgotten empty group — but a policy on it is a standing
grant to every principal the organization will ever have, including the ones
nobody has created yet. That is a *high*; a genuinely empty group is a *medium*.

**`iam.users.owner-daily-driver`.** The Organization Owner is above IAM, not
inside it: no policy grants its permissions and no policy can scope them. An
owner-bound API key therefore cannot be restricted, cannot be audited by reading
policies, and does not appear in anybody's access review.

## The listings

Each subcommand is one call, for when you want the inventory rather than the
judgement.

```
$ mlab-scw iam groups

  Groups

  NAME              ALL USERS  ALL APPS  CREATED               DESCRIPTION
  Administrators    false      false     2022-05-17  (4y ago)
  Editors           false      false     2022-05-17  (4y ago)
  All Users         true       false     2026-03-02  (6mo ago)  managed by Scaleway…
  All Applications  false      true      2026-03-02  (6mo ago)  managed by Scaleway…

  4 groups
```

`iam keys` shows the bearer as an id; `iam audit` resolves it to a name, which
is why the audit is the one to read.

## JSON

```json
{
  "organizationId": "aaaaaaaa-1111-2222-3333-444444444444",
  "inventory": {"users": 1, "applications": 4, "apiKeys": 15,
                "policies": 9, "groups": 5, "sshKeys": 1},
  "findings": [{"id": "iam.api-keys.never-expires", "severity": "critical",
                "subject": "platform-deploy · SCWEXAMPLEACCESSKEY1",
                "detail": "no expiry date: …"}],
  "gaps": [],
  "notImplemented": ["iam.logs.grant-outside-hours", "iam.logs.coverage",
                     "iam.jwts.foreign-ip"]
}
```

```bash
mlab-scw iam -o json | jq -r '.findings[] | select(.severity=="critical") | .subject'
mlab-scw iam -o json | jq -r '.findings | group_by(.id)[] | "\(length)\t\(.[0].id)"' | sort -rn
mlab-scw iam -o json | jq '.gaps'
```

## Permissions

`IAMReadOnly` reads everything above. Without it the command cannot even resolve
the organization, and says so rather than sending a request that would come back
as an unhelpful `400`.

The narrower sets — `IAMUserReadOnly`, `IAMApplicationReadOnly`,
`IAMGroupReadOnly`, `IAMPolicyReadOnly`, `SSHKeysReadOnly` — each open part of
it. The report names whichever part it could not read.
