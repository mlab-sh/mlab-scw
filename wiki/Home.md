# mlab-scw

A CLI over the Scaleway API, built as a base for read-only cloud posture
audits. **Every request it makes is a GET.** There is no flag that sends
anything else.

```bash
mlab-scw catalog --permissions   # the policy to create
mlab-scw login --name prod       # once
mlab-scw whoami                  # what that key can actually reach
mlab-scw iam                     # who can do what, and what is wrong with it
mlab-scw exposure                # what answers from the internet
mlab-scw quiet                   # what nobody has looked at in years
```

## Where to go

**Getting going**
- [Install](Install) — build it, and create the API key it should use.
- [Configuration](Configuration) — profiles, the key manager, precedence.

**One page per command**
[catalog](Catalog) · [iam](Iam) · [exposure](Exposure) · [quiet](Quiet) · [login](Login) · [ping](Ping) · [whoami](Whoami) ·
[project](Project) · [api](Api) · [profile](Profile) · [config](Config) ·
[completions](Completions)

**Concepts worth ten minutes**
- [Surfaces](Surfaces) — how the API is shaped, and the four ways that shape
  produces a wrong answer.
- [Output](Output) — the human render, `-o json`, and what goes to which stream.
- [Secrets](Secrets) — why a read-only API key is not read-only in the way you
  would hope.

**Project**
- [Roadmap](Roadmap) — what is built, and what phase two is.

## A note on the examples

Every identifier in this wiki is invented. Access keys, organization IDs,
project IDs, addresses and names have the right *shape* and nothing else; none
of them belongs to a real account. The convention throughout is:

| thing | placeholder |
| --- | --- |
| access key | `SCWEXAMPLEACCESSKEY0` |
| organization | `aaaaaaaa-1111-2222-3333-444444444444` |
| projects | `bbbbbbbb-…`, `cccccccc-…` |
| profile names | `lab`, `prod` |
