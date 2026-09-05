# Install

## Build

A recent Rust toolchain is all it needs.

```bash
git clone https://github.com/mlab-sh/mlab-scw.git
cd mlab-scw
cargo build --release
```

The binary lands at `target/release/mlab-scw`. During development,
`cargo run -- <command>` works the same way; every example in this wiki is
written as `mlab-scw <command>` and translates directly.

```bash
cargo test        # 57 tests, none of which touch the network
cargo clippy --all-targets
```

## Create the API key

The tool wants an API key that belongs to an **application of its own**, not to
you. Two reasons, and the second is the one that matters:

1. A key bound to a person inherits every permission that person is ever given,
   including the ones granted after the key was made.
2. When the audit key turns up in an audit trail, in a leaked file, or in a
   billing anomaly, you want to know immediately that it is the audit key and
   not somebody's console session.

In the console:

1. **IAM → Applications → Create an application.** Call it something that says
   what it is — `mlab-scw-audit`.
2. **IAM → Policies → Create a policy**, principal = that application.
3. Add the read-only permission sets. The tool prints exactly which ones,
   derived from what it intends to read rather than guessed at:

   ```bash
   mlab-scw catalog --permissions
   ```

   Scope them to the projects you mean to audit. Organization scope is right
   only if the account really is one project.
4. **IAM → API keys → Generate an API key**, bearer = that application. Set an
   **expiry**. The secret key is shown once.

Three of those permission sets are worth dropping unless the account uses the
product, because they return live credentials rather than descriptions:
`AppleSiliconReadOnly`, `ElasticMetalReadOnly` and `DomainsDNSReadOnly`. See
[Secrets](Secrets).

## First run

```bash
mlab-scw login --name prod
mlab-scw ping
mlab-scw whoami
```

`login` asks for the access key, then the secret key without echoing it, checks
the shape of both before spending a request, verifies them, resolves the
organization and writes `~/.mlab/scw.conf` with mode 0600 in a 0700 directory.

## Shell completion

```bash
mlab-scw completions zsh > ~/.zfunc/_mlab-scw
```

See [completions](Completions) for the other shells.
