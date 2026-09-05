# Phase 1 — test plan

Everything below is a `cargo run -- …` you can paste. Nothing here writes to
your account: every request the tool makes is a GET.

Two things to know before you start:

- **Set an isolated config while you poke at it**, so you never touch a profile
  you rely on:
  ```bash
  export MLAB_SCW_CONFIG=/tmp/scw-test.conf
  ```
  Unset it to go back to `~/.mlab/scw.conf`.
- **Progress goes to stderr, results to stdout**, so `| jq` works while a
  spinner is running.

---

## 1. No credentials needed

These touch nothing. Run them first — if the catalogue looks wrong, everything
after it is wrong too.

```bash
cargo run -- --help
cargo run -- --version
```

```bash
cargo run -- catalog                                   # 36 products, 99 resources
cargo run -- catalog iam                               # one product, in prose
cargo run -- catalog rdb
cargo run -- catalog vpc-gw
cargo run -- catalog nope                              # should list the valid keys
```

```bash
cargo run -- catalog --checks                          # 221 checks, worst first
cargo run -- catalog --checks --severity critical      # 41
cargo run -- catalog --checks --severity high          # 116: critical AND high
cargo run -- catalog --checks k8s
```

```bash
cargo run -- catalog --permissions                     # the policy to attach
cargo run -- catalog -o json | jq -r '.[] | .path' | head
cargo run -- catalog -o json | jq -r 'group_by(.permission)[] | "\(length)\t\(.[0].permission)"' | sort -rn
cargo run -- catalog --checks -o json | jq -r '.[] | select(.severity=="critical") | .id'
```

```bash
cargo run -- completions zsh | head -5
cargo run -- completions fish | head -5
```

**What to look for:** does the catalogue match the account you actually have?
Products you do not use are noise in the policy; products you use that are
*missing* are the important feedback.

---

## 2. The key manager

```bash
cargo run -- config path
cargo run -- config show                                # empty at first
```

Shape checks, before any request is spent:

```bash
cargo run -- login --non-interactive --name bad --access-key nope --secret-key 00000000-1111-2222-3333-444444444444
cargo run -- login --non-interactive --name bad --access-key SCWEXAMPLEACCESSKEY0 --secret-key not-a-uuid
```

Both should refuse with an explanation, and write nothing.

A wrong secret key, which does reach the API:

```bash
cargo run -- login --non-interactive --name bad --access-key SCWEXAMPLEACCESSKEY0 --secret-key 00000000-1111-2222-3333-444444444444
```

Should stop at the 401 and save nothing. Check:

```bash
cargo run -- config show
```

Now the real one:

```bash
cargo run -- login --name prod
```

It asks for the profile name, the access key, then the secret key **without
echo**. It should resolve your organization by itself. Then:

```bash
cargo run -- config show                                # secret masked to ****xxxx
cargo run -- profile list
cargo run -- profile show prod
ls -l "$(cargo run -q -- config path)"                  # must be -rw-------
```

Re-running `login` on the same profile should keep everything you leave blank —
that is the key-rotation path:

```bash
cargo run -- login --name prod
```

---

## 3. Reaching the API

```bash
cargo run -- ping
cargo run -- ping -o json | jq
```

**What to look for:** both probes `ok`. If IAM says `denied`, that is a valid
key with no IAM permission set — tell me, because it changes what `whoami` can
say.

```bash
cargo run -- whoami
cargo run -- whoami -o json | jq -r '.grants[] | "\(.permissionSet)\t\(.scope)\t\(.on)"'
```

**What to look for:**

- Is the principal an **application** or your **user**? It should warn if it is
  a user.
- Does it warn about **no expiry**?
- Does the grant list match the policy you created — same permission sets, same
  scope, right number of projects?
- If you are in any **groups**, do the grants they carry show up?

```bash
cargo run -- project
cargo run -- project -o json | jq -r '.[].name'
```

**What to look for:** does the project count match the console? Fewer means the
key is scoped narrower than you think, which is exactly the thing every later
report has to state.

---

## 4. The raw API

Paths come straight out of `catalog`. Substitute a zone or region you actually
use.

```bash
cargo run -- api /iam/v1alpha1/api-keys --list -Q organization_id={org}
cargo run -- api /iam/v1alpha1/users    --list -Q organization_id={org}
cargo run -- api /iam/v1alpha1/policies --list -Q organization_id={org}
```

```bash
cargo run -- api '/instance/v1/zones/{zone}/servers'         --list --zone fr-par-1 --per-page
cargo run -- api '/instance/v1/zones/{zone}/security_groups' --list --zone fr-par-1 --per-page
cargo run -- api '/instance/v1/zones/{zone}/ips'             --list --zone fr-par-1 --per-page
```

```bash
cargo run -- api '/k8s/v1/regions/{region}/clusters'            --list --region fr-par
cargo run -- api '/rdb/v1/regions/{region}/instances'           --list --region fr-par
cargo run -- api '/registry/v1/regions/{region}/namespaces'     --list --region fr-par
cargo run -- api '/containers/v1beta1/regions/{region}/containers' --list --region fr-par
cargo run -- api '/secret-manager/v1beta1/regions/{region}/secrets' --list --region fr-par
cargo run -- api '/vpc/v2/regions/{region}/private-networks'    --list --region fr-par
cargo run -- api '/lb/v1/zones/{zone}/lbs'                      --list --zone fr-par-1
cargo run -- api /domain/v2beta1/dns-zones --list
```

Audit Trail is the one with token paging, and it needs the organization:

```bash
cargo run -- api '/audit-trail/v1alpha1/regions/{region}/events' --list --region fr-par \
  --token-paging --limit 5 -Q organization_id={org}
```

Three endpoints want a parameter the Go SDK does not mark as required. The
catalogue records each by name — `mlab-scw catalog -o json | jq -r '.[] | select(.needs != "")'`:

```bash
cargo run -- api /iam/v1alpha1/rules --list -Q policy_id=SOME_POLICY_UUID
cargo run -- api /iam/v1alpha1/jwts  --list -Q audience_id=YOUR_USER_UUID
cargo run -- api '/mnq/v1beta1/regions/{region}/sqs-credentials' --list --region fr-par -Q project_id=SOME_PROJECT_UUID
```

A `412 precondition_failed` on the last one is not a bug: it means Messaging &
Queuing is not activated in that project. The hint says so.

A single object rather than a list:

```bash
cargo run -- api /iam/v1alpha1/api-keys/YOUR_ACCESS_KEY
```

Refusals to guess — both should error rather than pick one:

```bash
cargo run -- api '/instance/v1/zones/{zone}/servers' --list          # no --zone
cargo run -- ping --region nowhere
```

Secret masking, if you use either product:

```bash
cargo run -- api '/apple-silicon/v1alpha1/zones/{zone}/servers' --list --zone fr-par-1
cargo run -- api /domain/v2beta1/ssl-certificates --list
```

**What to look for:** a `! N secret value(s) … replaced by their length` warning.
If a credential comes through in the clear, that is the most important bug you
can find, so tell me the field name — **not** the value.

Piping:

```bash
cargo run -q -- api '/instance/v1/zones/{zone}/security_groups' --list --zone fr-par-1 --per-page -o json \
  | jq -r '.[] | select(.inbound_default_policy == "accept") | .name'
```

---

## 5. Output and rendering

```bash
cargo run -- project                    # dates should read "2022-05-17  (4y ago)"
cargo run -- project -o json            # raw timestamps, no annotation
cargo run -- project -q                 # no progress, no warnings
NO_COLOR=1 cargo run -- project         # no escape sequences
cargo run -- project -o json > /tmp/p.json && cat /tmp/p.json    # warnings still on the terminal
```

---

## 6. Cleaning up

```bash
cargo run -- profile remove prod
unset MLAB_SCW_CONFIG
```

---

## The feedback I actually want

1. **Anything in the catalogue that is wrong or missing** for the products you
   run. Wrong path, wrong permission set, a check that is nonsense in practice,
   a product you use that is not there.
2. **Any command whose output you had to read twice.** Column choice, wording,
   what is missing from the human render that you went to `-o json` for.
3. **Any error message that did not tell you what to do next.**
4. **Whether the auto-picked table columns show you the right things.** They are
   ordered identity, then booleans, then the rest, with `project_id` and
   `organization_id` last — because in this API a boolean is nearly always a
   control. If a column you needed got pushed off, tell me which.
5. **Anything that felt slow**, and roughly how many resources you have — the
   client backs off on 429 but nothing runs in parallel yet, which is phase 2.
6. **Whether `whoami` matches reality.** It is the command everything else rests
   on: if it under-reports a grant, every later "clean" is a lie.
