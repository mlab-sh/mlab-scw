# Secrets

Why a read-only Scaleway API key is not read-only in the way you would hope.

## The claim

Scaleway's permission sets come in matched pairs: `InstancesFullAccess` and
`InstancesReadOnly`, `KubernetesFullAccess` and `KubernetesReadOnly`, and so on
for thirty-odd products. The read-only half is described as "list and read
access", and it is reasonable to hand one out on the understanding that the
worst it can do is describe.

That understanding is wrong in a few specific, documented places. Not because
the permission is broken, but because some products' *state* includes a live
credential, and reading state means reading it.

## What a read call returns

| Permission set | Endpoint | What comes back |
| --- | --- | --- |
| `AppleSiliconReadOnly` | `GET /apple-silicon/v1alpha1/zones/{zone}/servers` | `sudo_password`, plus `vnc_url` and `ssh_username`. Administrative access to the machine. |
| `ElasticMetalReadOnly` | `GET /baremetal/v1/zones/{zone}/servers/{id}/bmc-access` | `url`, `login`, `password` for the out-of-band console: keyboard and screen below the operating system. |
| `DomainsDNSReadOnly` | `GET /domain/v2beta1/ssl-certificates` | `private_key` and `certificate_chain` of managed certificates. Impersonation of the site. |
| `DomainsDNSReadOnly` | `GET /domain/v2beta1/domains/{domain}/auth-code` | The EPP code, which authorises a transfer of the domain away from the account. |
| `DomainsDNSReadOnly` | `GET /domain/v2beta1/dns-zones/{zone}/tsig-key` | The zone's signing key. |
| `InstancesReadOnly` | `GET /instance/v1/zones/{zone}/servers/{id}/user_data` | cloud-init, verbatim — whatever anybody pasted into it. |
| `ContainersReadOnly`, `FunctionsReadOnly`, `ServerlessJobsReadOnly` | the resource itself | `environment_variables`, verbatim. `secret_environment_variables` is the field that is masked; the plain one is not. |
| `MessagingAndQueuingReadOnly` | `GET /mnq/v1beta1/regions/{region}/nats-credentials` | a NATS credentials file, whole. |

The pattern is the same each time: the credential *is* the state. There is no
version of "describe this Mac runner" that omits the password Scaleway set on
it, so a permission set that describes it hands it over.

## The one that does it right

Secret Manager is the counter-example, and worth knowing about because it shows
the split is deliberate rather than accidental:

- `SecretManagerReadOnly` — "List and read secrets' metadata (name, tags,
  creation date, etc.). **Does not include permissions for data (versions)
  accessing** or editing".
- `SecretManagerSecretAccess` — read access to version data, as a separate
  grant.

So a key can enumerate every secret in the account, see how many versions each
has and when they were last rotated, and never be able to read one. That is
exactly the shape an audit wants, and it is why this tool asks for
`SecretManagerReadOnly` and nothing more.

## What this tool does about it

1. **It never asks for a value it does not need.** The catalogue contains no
   path that returns secret data by design: `secrets/{id}/versions/{rev}/access`
   is not in it, and neither is `kubeconfig`.

2. **It masks what arrives anyway.** The endpoints above return credentials
   whether or not you wanted them, so any response printed by `mlab-scw api`
   passes through the redactor in `src/scw/secrets.rs` first. A secret is
   replaced by `<redacted:N>` — its length and nothing else, because a length
   is not a secret and is what a strength check needs. The count is reported,
   because *how many* credentials a read-only key just received is itself the
   finding.

3. **`--unsafe-values` exists, and says so.** Sometimes the value is what you
   came for. The flag is named for what it does to your terminal scrollback,
   your ticket system and your screen recording.

The list lives in `src/scw/secrets.rs` and is explicit, never a substring rule. `data` is what a DNS
record calls its value and `key` is a map key in a dozen places; a redactor
noisy enough to blank those is one that gets switched off within a day.

## What to do with this

- Give the audit key an **application of its own**, never a person's key.
- Attach exactly what `mlab-scw catalog --permissions` prints, and drop
  `AppleSiliconReadOnly`, `ElasticMetalReadOnly` and `DomainsDNSReadOnly` if
  the account does not use those products. Those three are the expensive ones.
- Set an **expiry**. `max_api_key_expiration_duration` in the organization's
  security settings makes it impossible to create one without.
- Treat the audit key as a credential of the same class as the things it can
  read — because in those three products, it is.
