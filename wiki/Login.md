# login

Create or update a profile, prove the credentials work, save them.

```bash
mlab-scw login                       # asks for everything
mlab-scw login --name prod
mlab-scw login --name prod --organization-id aaaaaaaa-1111-2222-3333-444444444444
```

Aliases: `configure`, `setup`.

## Why there is a wizard

A Scaleway API key is two opaque strings that differ only in shape, the secret
half is shown exactly once at creation, and pasting it into the wrong field
produces a `401` that says nothing useful. So:

- the secret is read **without echo**;
- both halves are **shape-checked before a request is spent** — an access key is
  `SCW` plus 17 uppercase alphanumerics, a secret key is a UUID;
- the profile is only written after the API has agreed the pair works.

## What a run looks like

```
$ mlab-scw login --name prod

  Profile name [prod]:
  Access key: SCWEXAMPLEACCESSKEY0
  Secret key:
  ✔ the credentials work
  › organization aaaaaaaa-1111-2222-3333-444444444444
  ✔ saved profile "prod" to /home/you/.mlab/scw.conf

  access key    SCWEXAMPLEACCESSKEY0
  secret key    ****4444
  organization  aaaaaaaa-1111-2222-3333-444444444444
  scope         every region and zone
  default       true

  › next: `mlab-scw whoami` to see what this key is allowed to read
```

## The ladder

Listing projects is the cheapest proof a credential works, but
`/account/v3/projects` **requires** an `organization_id`, and nothing in an API
key carries one. So the order is forced by the API rather than chosen:

1. `GET /iam/v1alpha1/api-keys/{access_key}` — proves the pair, names a
   principal.
2. `GET /iam/v1alpha1/applications/{id}` (or `/users/{id}`) — yields the
   organization.
3. `GET /account/v3/projects?organization_id=…` — proves `ProjectReadOnly`.

Each rung fails differently, and the difference is the point:

| answer | means | what login does |
| --- | --- | --- |
| 401 | the secret key is wrong | stops; nothing is saved |
| 404 | the secret key works, the *access* key names nothing | stops, and says which |
| 403 | both work, the key holds no IAM permission set | continues, and asks for the organization |

A key that cannot read IAM is a perfectly valid audit key. It just has to be
told which organization it is auditing — the console shows it on the IAM page,
above the user list.

## Rotating a key

`login` on an existing profile uses it as the source of defaults, so rotation is
one command and a blank answer to everything you are not changing:

```bash
mlab-scw login --name prod     # blank keeps the stored value
```

Then delete the old key in the console.

## Flags

| flag | effect |
| --- | --- |
| `--name`, `-n` | profile to create or update |
| `--no-default` | do not make it the default profile |
| `--no-verify` | save without testing the credentials |
| `--non-interactive` | ask nothing; every value must come from flags or the environment |

`--non-interactive` is for CI, and it fails rather than prompting when something
is missing:

```bash
SCW_ACCESS_KEY=… SCW_SECRET_KEY=… SCW_DEFAULT_ORGANIZATION_ID=… \
  mlab-scw login --non-interactive --name ci
```

Prefer the environment to `--secret-key`: a command line is visible to every
other user on the machine.
