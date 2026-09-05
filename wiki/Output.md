# Output

Two formats, three streams, and one rule that makes them work together.

## The rule

**stdout carries the result. stderr carries everything else.**

Progress spinners, status lines, warnings and prompts all go to stderr, so this
stays parsable while a spinner is running:

```bash
mlab-scw whoami -o json | jq -r '.grants[].permissionSet'
```

and this still shows you what went wrong:

```bash
mlab-scw project -o json > projects.json     # warnings still reach the terminal
```

## Formats

| flag | what |
| --- | --- |
| *(default)* | `human` — a quiet terminal render |
| `-o json` | raw JSON on stdout, untouched |

`-o json` humanizes nothing. A pipeline sees exactly what the API returned, so
`created_at` is `2024-03-02T10:11:45Z`, not `2y ago`, and `size` is a byte
count. The only thing ever removed is a secret value — see
[Secrets](Secrets).

The format is resolved once at startup, from `-o`, then `SCW_OUTPUT` /
`MLAB_SCW_OUTPUT`, then the profile's `output` field.

## The human render

Two-space indent, dimmed labels, one blank line around each block. Lists become
tables; **columns that carry no data on this account are dropped**, so a table's
width tells you something rather than being padded with empties.

Values are annotated only where the annotation is unambiguous:

```
  created_at  2022-05-17T17:47:51.178901Z  (4y ago)
  expires_at  2026-09-12T20:57:42.663Z  (in 6d)
  size        107374182400  (100.0 GiB)
```

Dates gain their distance from now, in both directions — an age is a finding and
so is an expiry. Byte counts gain a unit. `memory_limit` and `cpu_limit` are
deliberately left raw: those are megabytes and millicores, and guessing wrong
prints a confident lie.

In a **table** a date is compressed further, to the day plus the age:

```
  NAME       CREATED
  default    2022-05-17  (4y ago)
```

The microseconds are eight characters of noise in a column, and what the column
is read for is "four years old". The full value is one `-o json` away.

Table columns, when the shape is only known at run time, are picked identity
first, then **booleans**, then the rest, with `project_id` and
`organization_id` last. In this API a boolean is almost always a control, and
two UUIDs nobody reads would otherwise crowd every switch off the table.

Status words are coloured by what they mean, not by where they appear: `running`
and `ready` green, `locked` and `error` red — `locked` is not a state a healthy
resource reaches, it means Scaleway has suspended it — `pending` and
`provisioning` amber, `public` red and `private` green.

A cell longer than 44 characters is clipped with an ellipsis so one field cannot
wreck the alignment; a UUID is 36 and still fits whole. Use `-o json` when you
need the untruncated value.

## Progress

A spinner appears on stderr only when all three are true:

1. the work has already run past 250 ms — a spinner that flashes and vanishes
   reads as a glitch, not as feedback;
2. stderr is a terminal;
3. `--quiet` was not passed and `CI` is not set.

Pipes, CI logs and tests therefore get clean output with no escape sequences.

| flag / variable | effect |
| --- | --- |
| `--quiet`, `-q` | silences everything this tool writes to stderr, including warnings |
| `MLAB_SCW_NO_PROGRESS` | silences it without silencing warnings |
| `CI` | disables animation, keeps warnings |
| `NO_COLOR` | disables colour (honoured by the colour library) |

## Exit codes

`0` on success, `1` on error. The error goes to stderr, prefixed with `✖`, with
the whole cause chain flattened onto it:

```
  ✖ reading the API key from IAM: API error 401 [denied_authentication]: authentication is denied
    hint: the secret key is wrong, expired, or belongs to a deleted application
```

`ping` is the one command with a nuanced exit: it fails only when *nothing*
reached the API. A `403` still proves the credentials authenticate.
