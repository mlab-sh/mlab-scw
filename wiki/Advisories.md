# advisories

What this account runs, against what has been published about it.

```bash
mlab-scw advisories --explain        # what a run would send, sending nothing
mlab-scw advisories --allow-web      # check the versions against the corpus
mlab-scw advisories                  # local cache only
mlab-scw advisories --severity high
```

Alias: `cve`.

## The only command that talks to anything else

Everything else in this tool speaks to `api.scaleway.com` and nowhere else. This
one asks [vuln.mlab.sh](https://vuln.mlab.sh) what has been published about the
software the account is running, so it is the only command that can leak. Three
rules hold it in place.

**It is opt-in, per run.** Without `--allow-web` the corpus is read from the
local cache only, and anything missing is reported as *unchecked* rather than as
clean.

**Only a product identifier leaves.** The request is a CPE and a page number:

```
GET https://vuln.mlab.sh/api/v1/cve?cpe=cpe:2.3:a:postgresql:postgresql&limit=100
```

No organization, no project, no resource id, no name, no address. What goes out
identifies software, never an account. `--explain` prints the exact list and
sends nothing — the honest form of "nothing leaves your machine unless you allow
it" is that you can read the payload first.

**It never probes.** The corpus is a document store. Asking it a question sends
no packet at anything you own, so the tool's promise that every request is a read
stays true.

## The report

```
$ mlab-scw advisories --allow-web

  What this account runs

  SOFTWARE    VERSION         WHERE
  Kubernetes  1.29.2          prod (fr-par)
  PostgreSQL  PostgreSQL-14   app (fr-par)
  Redis       7.0.5           cache (fr-par-1)

  3 components

  Findings

  CRITICAL

  rdb.instances.known-cve
  PostgreSQL runs PostgreSQL-14, which 4 published advisories cover, 1 of them
  in the KEV catalogue of vulnerabilities being exploited now. Worst CVSS 9.8.
  CVE-2026-1094, CVE-2026-1097, CVE-2026-2201, CVE-2026-4410
    app (fr-par)

  1 critical  ·  2 medium

  Not checked
    MySQL: 1328 advisories exist and 600 were read
    OpenSearch: the corpus files no advisory under cpe:2.3:a:amazon:opensearch

  3 corpus lookup(s) fetched from vuln.mlab.sh. 6 of the catalogue's checks are
  about published advisories and are derived here.
```

## Grading

An advisory is a document. An advisory whose **affected range covers your
version** is a finding. An advisory **in the KEV catalogue** is a finding about
something being exploited today. Reporting all three the same way is how a
vulnerability report becomes wallpaper.

| severity | when |
| --- | --- |
| `critical` | at least one matching advisory is in KEV |
| `high` | none in KEV, worst CVSS 9.0 or above |
| `medium` | otherwise |

A lower CVSS that is being used *today* outranks a higher one that is not.

## Version matching, not name matching

The corpus is queried by CPE — `cpe:2.3:a:postgresql:postgresql` — and every
advisory carries its bounds:

```json
{"criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
 "version_start_including": "13.0", "version_end_excluding": "13.5"}
```

So `13.2` is a finding and `14.11` is not. Three details decide whether that
comparison is right, and each has a test:

- **Components compare as numbers.** `10.0.10` is *after* `10.0.7`, which a
  string sort gets backwards — and getting it backwards turns a real advisory
  into silence.
- **A missing component is zero.** `14` and `14.0` are the same version; `14` is
  older than `14.1`.
- **Another vendor's range says nothing about yours.** One advisory routinely
  covers several products. Matching on the advisory rather than on its entry for
  *your* CPE is how a tool reports Splunk's vulnerability as PostgreSQL's.

An unparseable version — `latest`, or a field the API left empty — is skipped
rather than guessed at. A confident answer with nothing behind it is worse than
no answer.

## Two ways this could lie, and what stops them

**A malformed CPE returns the whole corpus.** The service does not refuse a
filter it cannot parse; it ignores it and answers with all three hundred
thousand advisories, which would arrive as findings about your Redis. So the
shape is checked before the request, and an implausible result count is treated
as a failure rather than as findings.

**A well-formed CPE can be filed under nothing.** MongoDB has no `mongodb:*`
product in the corpus at all. Zero advisories is not a clean bill of health — it
means nothing was checked. Every such product is named under **Not checked**, and
MongoDB is deliberately absent from the table rather than present and always
silent.

## The check that needs nobody else

`functions.functions.eol-runtime` uses no corpus. Scaleway publishes its own
verdict on every runtime it offers:

```
name=node26  language=Node  version=26  status=available
name=node20  language=Node  version=20  status=end_of_support
name=node14  language=Node  version=14  status=end_of_life
```

So the command joins each function's runtime against that list. `end_of_life` is
a *high*, `end_of_support` a *medium*, and the platform is the authority — asking
anyone else would be worse.

## Cache

`~/.mlab/scw/cve-<cpe>.json`, 0600 inside a 0700 directory, one day of freshness.
A repeated audit costs nothing, and a run without `--allow-web` still has real
answers as long as the cache holds them. A stale cache is used and reported as
used, because a stale corpus is a far better answer than none.

## Verifying the network path

One test reaches the corpus, and it is opt-in:

```bash
cargo test -- --ignored corpus_answers
```

It proves the four things offline tests cannot: that the `cpe` filter is honoured
rather than ignored, that paging terminates, that the answers carry the version
bounds the grading depends on, and that a real version lands inside a real range.
