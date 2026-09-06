# Test plan — phases 1 to 5

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

## 4. The IAM audit (phase 2)

The first real audit. Eight global calls, no locality sweep.

```bash
cargo run -- iam
```

**What to look for, in order of how much it would bother me if it were wrong:**

1. **Does the top of the report match reality?** The inventory counts, and the
   `! this report is partial` block if any listing was refused.
2. **Is any finding simply false?** A check that fires on something correct is
   worse than a check that does not exist — tell me the id and what is actually
   the case.
3. **Is any finding true but useless?** Noise is the other way an audit tool
   stops being read.
4. **Is anything obviously missing** that you would look at by hand?

Severity floors, and the JSON:

```bash
cargo run -- iam audit --severity critical
cargo run -- iam audit --severity high
cargo run -- iam -o json | jq -r '.findings | group_by(.id)[] | "\(length)\t\(.[0].id)"' | sort -rn
cargo run -- iam -o json | jq '.gaps, .notImplemented'
```

The specification behind the report, side by side with it:

```bash
cargo run -- catalog iam
cargo run -- catalog iam --checks
```

Every check in the second list is either emitted by `iam` or named at the bottom
of the report as underived. If you find one that is in neither, that is a bug in
the bookkeeping, not just in the docs.

The inventories, one call each:

```bash
cargo run -- iam users
cargo run -- iam applications
cargo run -- iam keys
cargo run -- iam policies
cargo run -- iam groups
cargo run -- iam ssh-keys
cargo run -- iam settings
```

Two checks worth confirming by hand against the console, because they are the
ones most likely to be subtly wrong:

- **`iam.groups.everyone`** — does any group with `ALL USERS` or `ALL APPS` true
  actually carry a policy? If yes it should be a *high*; if no it should not
  appear at all.
- **`iam.policies.unused`** — is each named policy really attached to a principal
  that cannot use it?

---

## 5. The public edge (phase 3)

The cross-product sweep: everything that answers from the internet, and what
stands in front of it. Around 160 calls in two seconds on a small account.

```bash
cargo run --release -- exposure
```

Use `--release`; the debug build makes 160 requests noticeably slower.

**What to look for, in order:**

1. **Is anything in the map wrong?** A row that is not actually reachable, or a
   `VERDICT` that misreads the control in front. This is the part no unit test
   can check for your account.
2. **Is anything missing from the map** that you know answers from the internet?
   That is the most valuable bug you can find here — a missed exposure is
   silent, and the report will look clean.
3. **Does the gap list at the top match what your key cannot read?**

```bash
cargo run --release -- exposure --map              # the inventory, no findings
cargo run --release -- exposure --severity critical
cargo run --release -- exposure --region fr-par    # one region
cargo run --release -- exposure --concurrency 16   # faster, less polite
```

```bash
cargo run --release -- exposure -o json | jq -r '.exposures[] | "\(.verdict)\t\(.kind)\t\(.endpoint)"'
cargo run --release -- exposure -o json | jq '.gaps'
cargo run --release -- exposure -o json | jq '.calls'
```

Three behaviours worth confirming deliberately, because each is a judgement
call I made rather than a fact the API states:

- **`unknown` is never guessed.** If a security group or ACL cannot be read, the
  row says `unknown` and no finding is emitted. Try a key without
  `InstancesReadOnly` and check that a public server appears as `unknown` rather
  than as `open`.
- **A 501 is not an error.** Scaleway answers `501 Not Implemented` for a
  product that does not run in a zone. Those are silent. If you see gap lines
  about products not existing somewhere, that is a regression.
- **Gaps are per product, not per locality.** A missing permission set should
  produce one line saying "denied in 10 localities", not ten lines.

---

## 6. The quiet products (phase 4)

Everything nobody looks at. Around 190 calls in three seconds.

```bash
cargo run --release -- quiet
```

**What to look for, in order:**

1. **Any finding that is false.** This command makes more judgement calls than
   the other two, and the credential detector is the one most able to be wrong
   in both directions.
2. **A credential in a plain environment variable that it did *not* find.** Look
   at your containers, functions and job definitions yourself and compare —
   a missed one is silent.
3. **A DNS record you know is dangling that it did not flag.**

```bash
cargo run --release -- quiet --severity critical
cargo run --release -- quiet -o json | jq -r '.findings | group_by(.id)[] | "\(length)\t\(.[0].id)"' | sort -rn
cargo run --release -- quiet -o json | jq '.gaps, .projects'
```

Four behaviours worth confirming deliberately, because each is a judgement I
made rather than a fact the API states:

- **The detector never prints the value.** Every `plaintext-secret` finding
  should name the variable and say *why*, and carry nothing you would mind
  pasting into a ticket. If a value appears anywhere in the output, that is the
  most serious bug in the tool.
- **It stays quiet on names that only mention a secret.** `TOKEN_TTL=3600`,
  `SECRET_NAME=prod-db-password`, `API_KEY_FILE=/run/secrets/key` and
  `DB_PASSWORD=${DB_PASSWORD}` must all produce nothing. Add one to a
  non-production container and check.
- **The marketplace is not your golden image.** `instance/images` returns
  Scaleway's whole catalogue. If you see thousands of findings about AlmaLinux
  or Ubuntu, the organization filter has regressed.
- **Project-scoped products are swept per project.** The header should say
  `projects: 4`, not `unknown`. Messaging & Queuing is the one that needs it.

The specification behind the report:

```bash
cargo run --release -- catalog --checks | grep -E "domain\.|iot\.|registry\.|secret-manager\."
```

---

## 7. Published advisories (phase 5)

The only command that talks to anything but `api.scaleway.com`. Start with the
one that sends nothing:

```bash
cargo run --release -- advisories --explain
```

It prints the exact requests a real run would make. **Read them before going
further** — that is the whole point of the flag. Each line should be a CPE and a
page size, and nothing about your account.

```bash
cargo run --release -- advisories                # local cache only
cargo run --release -- advisories --allow-web    # actually check
cargo run --release -- advisories --allow-web --severity high
cargo run --release -- advisories -o json | jq '.components, .coverage'
```

**What to look for:**

1. **Does the component table match what you actually run?** A version listed
   wrong is a finding graded against the wrong range.
2. **Does anything you run *not* appear?** The table only knows six products —
   Kubernetes, PostgreSQL, MySQL, Redis, Kafka, OpenSearch. If you run something
   else worth checking, tell me and I will verify its CPE against the corpus
   before adding it.
3. **Is the `Not checked` block honest?** A product the corpus files nothing
   under must appear there, never as silence.

Four behaviours worth confirming deliberately:

- **Nothing goes out without the flag.** Run `advisories` with no `--allow-web`
  on a machine with an empty `~/.mlab/scw/` and confirm it reports everything as
  unchecked rather than as clean.
- **The cache works.** Two `--allow-web` runs in a row; the second should say
  "served from the local cache" and be instant. `ls -l ~/.mlab/scw/` — the files
  must be `-rw-------`.
- **KEV outranks CVSS.** A matching advisory in KEV is a `critical` even at a
  lower CVSS than a `high`. That is deliberate: it means somebody is using it
  today.
- **The network path itself**, which no offline test can prove:

  ```bash
  cargo test -- --ignored corpus_answers
  ```

  It checks that the CPE filter is honoured rather than ignored, that paging
  terminates, and that a real version lands inside a real published range.

---

## 8. The raw API

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

## 9. Output and rendering

```bash
cargo run -- project                    # dates should read "2022-05-17  (4y ago)"
cargo run -- project -o json            # raw timestamps, no annotation
cargo run -- project -q                 # no progress, no warnings
NO_COLOR=1 cargo run -- project         # no escape sequences
cargo run -- project -o json > /tmp/p.json && cat /tmp/p.json    # warnings still on the terminal
```

---

## 10. Cleaning up

```bash
cargo run -- profile remove prod
unset MLAB_SCW_CONFIG
```

---

## The feedback I actually want

Phase 5 first, because it is the only part that sends anything anywhere:

1. **Anything in `--explain` you would not want sent.** That output is the
   contract; if it carries something about your account, that is the most
   serious bug here.
2. **A component listed with the wrong version**, or one you run that the table
   does not know about.
3. **Anything reported as clean that should have read as unchecked.**

Then phase 4:

4. **Any `quiet` finding that is false**, any plaintext credential it missed,
   and any value that appears in the output.

Then phase 3:

5. **Anything reachable from the internet that the map does not list**, or any
   map row with the wrong verdict.

Then phases 2 and 1:

6. **Any `iam` finding that is false, or true but not worth a line.**
7. **Anything in the catalogue that is wrong or missing** for the products you
   run.
8. **Any command whose output you had to read twice**, or any error message that
   did not tell you what to do next.
