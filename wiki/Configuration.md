# Configuration

## The file

`$HOME/.mlab/scw.conf`, JSON, mode 0600 inside a 0700 directory. It holds any
number of named profiles plus the name of the default one.

```json
{
  "default": "prod",
  "profiles": {
    "prod": {
      "access_key": "SCWEXAMPLEACCESSKEY0",
      "secret_key": "00000000-1111-2222-3333-444444444444",
      "organization_id": "aaaaaaaa-1111-2222-3333-444444444444"
    },
    "lab": {
      "access_key": "SCWEXAMPLE2NDKEY0AB",
      "secret_key": "00000000-1111-2222-3333-999999999911",
      "organization_id": "aaaaaaaa-1111-2222-3333-444444444444",
      "region": "fr-par"
    }
  }
}
```

Every identifier in this wiki is invented; see [Home](Home#a-note-on-the-examples).

`mlab-scw config path` prints the location; `mlab-scw config show` prints the
contents with secret keys masked. The tool warns at startup if the file is
readable by anyone else.

Set `MLAB_SCW_CONFIG` to move it.

## The key pair

A Scaleway API key is two strings:

- the **access key**, `SCW` followed by 17 uppercase alphanumerics. An
  identifier, not a secret. IAM is queried by it, which is why `whoami` needs
  it stored.
- the **secret key**, a UUID. This is the `X-Auth-Token` value, and it is shown
  exactly once, when the key is created.

The same pair also signs Object Storage requests over S3 SigV4 — one credential
covers both surfaces. Note that an API key carries a *preferred Project for
Object Storage*, fixed at creation: S3 calls made with it only ever see that
one project's buckets, whatever the key's IAM policy says.

`login` shape-checks both halves before spending a request, because the most
common mistake by far is pasting the access key into both fields, and the 401
that produces says nothing useful.

## Finding the organization

Scaleway has no "who am I" endpoint, and the two obvious candidates each fall
one field short:

- `GET /account/v3/projects` is the natural first call, and it **requires**
  `organization_id`. Without one the API answers `400 invalid_arguments`.
- `GET /iam/v1alpha1/api-keys/{access_key}` needs no organization, but the API
  key object does not carry one either. It names a principal.

So the organization is one hop further out — key, then the application or user
bearing it, which does carry `organization_id`. That hop needs an IAM read
permission, so it can legitimately fail on a perfectly valid key, and `login`
then asks for the organization instead. The console shows it on the IAM page,
above the user list.

Once recorded in the profile, neither hop is made again.

`login` reads the three failure modes apart, because they mean different
things:

| answer | means |
| --- | --- |
| 401 | the secret key is wrong. Fatal; nothing is saved. |
| 404 | the secret key works, the *access* key names nothing. |
| 403 | both work; the key simply holds no IAM permission set. |

## Precedence

Flags override environment variables, which override the profile.

Both `MLAB_SCW_*` and plain `SCW_*` are read. The second spelling is
deliberate: `SCW_ACCESS_KEY`, `SCW_SECRET_KEY`, `SCW_DEFAULT_ORGANIZATION_ID`,
`SCW_DEFAULT_PROJECT_ID`, `SCW_DEFAULT_REGION` and `SCW_DEFAULT_ZONE` are what
Scaleway's own CLI and the Terraform provider already export.

Prefer the environment to `--secret-key`: a command line is visible to every
other user on the machine.

## Scope

| Flag | Effect |
| --- | --- |
| *(none)* | every region and every zone |
| `--region fr-par` | that region, and its three zones |
| `--zone nl-ams-2` | that zone, and its parent region for regional products |
| `--project-id …` | fills `{project}` in [`api`](Api); no command narrows itself by it yet |
| `--organization-id …` | the organization IAM and Billing are asked about |

Leaving the project unset is usually right for an audit: without it the API
answers for every project the key can see, and `mlab-scw project` prints what
that turned out to be.

## Fields a profile can hold

| field | meaning |
| --- | --- |
| `access_key` | the identifier half of the pair; IAM is queried by it |
| `secret_key` | the `X-Auth-Token` value |
| `organization_id` | recorded at login, so the IAM hops are not repeated |
| `project_id` | fills `{project}` in [`api`](Api); nothing else reads it yet. Leave it empty for an audit |
| `region`, `zone` | narrows the sweep; empty means everywhere |
| `api_url` | override the API base, for a proxy or a test double |
| `output` | `human` or `json` |

Empty fields are not written to the file at all, so a profile stays readable.

## Rotating a key

`login` on an existing profile keeps everything except what you retype, so
rotation is:

```bash
mlab-scw login --name prod        # blank answers keep the old values
```

and then delete the old key in the console.
