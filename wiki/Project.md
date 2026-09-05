# project

The projects the key can see.

```bash
mlab-scw project
mlab-scw project --limit 5
mlab-scw project -o json
```

Alias: `projects`.

## Why a short command matters

Every regional and zonal listing in the [catalogue](Catalog) is filtered by
project. What this prints is therefore the boundary of every other answer the
tool will ever give, and the first thing to put at the top of a report.

Most listings take `project_id` as an *optional* filter: omit it and the API
answers for every project the key can reach. That is what an audit wants, and it
makes this list the record of what "every project" turned out to mean.

Two exceptions, both in the catalogue's `needs` column: every IAM listing
requires an `organization_id`, and every Cockpit call requires a `project_id` —
so observability has to be swept project by project or it is not swept at all.

## Output

```
$ mlab-scw project

  Projects

  NAME       ID                                    CREATED
  default    aaaaaaaa-1111-2222-3333-444444444444  2022-05-17  (4y ago)
  platform   bbbbbbbb-1111-2222-3333-444444444444  2025-04-03  (17mo ago)
  analytics  cccccccc-1111-2222-3333-444444444444  2025-06-11  (15mo ago)
  sandbox    dddddddd-1111-2222-3333-444444444444  2026-01-24  (7mo ago)

  4 projects
```

Two things about that output.

**The dates.** In a table a timestamp loses its time and gains its age: the
microseconds of `2022-05-17T17:47:51.178901Z` are eight characters of noise, and
what the column is read for is "four years old". A block prints the whole thing;
`-o json` never annotates anything.

**The `default` project shares the organization's UUID.** That is how Scaleway
works, not a rendering bug — which is also why an API key that was never given a
preferred Object Storage project reports the organization ID there.

## The organization

`GET /account/v3/projects` **requires** `organization_id`, and an API key does
not carry one — see [Surfaces](Surfaces#3-there-is-no-who-am-i-and-the-bootstrap-is-awkward).
If the profile recorded one at login, it is used. Otherwise the command resolves
it through IAM, and if that is denied it says so plainly rather than sending a
request that would come back as an unhelpful `400`:

```
  ✖ listing projects needs an organization id, and this key cannot read its own
    principal in IAM to find one. Pass --organization-id, set
    SCW_DEFAULT_ORGANIZATION_ID, or run `mlab-scw login` to record it — the
    console shows it on the IAM page.
```

## Reading the result

Two things are worth noticing here rather than later:

- **Fewer projects than the organization has.** The sweep is partial, and the
  report has to say so. Compare with what the console shows.
- **Everything in `default`.** No blast-radius boundary anywhere: one
  compromised credential reaches the whole estate.
