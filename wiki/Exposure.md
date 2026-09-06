# exposure

What answers from the internet, and what stands in front of it.

```bash
mlab-scw exposure                       # the map, then the findings
mlab-scw exposure --map                 # the map only
mlab-scw exposure --severity critical
mlab-scw exposure --region fr-par       # narrow the sweep
mlab-scw exposure -o json | jq '.exposures'
```

Alias: `edge`.

## The join is the point

No single Scaleway endpoint answers "what of mine is reachable". Addresses live
in Instances, Elastic Metal, Apple silicon, Flexible IP and IPAM. Ports live in
load-balancer frontends, gateway PAT rules and database endpoints. Whether any
of it is *narrowed* lives in a different call again — a security group, an ACL
list, a `privacy` flag.

An exposure with a tight ACL and one with none look identical in an inventory,
and are not the same finding. So the command sweeps in three rounds:

1. **22 resources** across every region and zone: everything that can hold an
   address or serve a request.
2. **The controls** hanging off what round one found: security-group rules per
   group, frontends and certificates per load balancer, ACLs per cluster and per
   database, node pools per cluster.
3. **The control on a control**: the allow-list on each frontend.

On a small account that is around 160 calls in two seconds, eight at a time.

## The map

```
$ mlab-scw exposure

  The public edge

  calls           160 across 14 localities
  reachable       2
  of those, open  2

  Exposure map

  VERDICT  KIND           NAME       WHERE     ENDPOINT                        PORTS  IN FRONT
  open     container      api        fr-par    api.example.fnc.fr-par.scw.…    443    privacy: public, no token required
  open     elastic metal  build-01   fr-par-2  203.0.113.40, 2001:db8::1              no platform firewall

  2 exposures
```

Three verdicts, and the third one matters as much as the first two:

| verdict | means |
| --- | --- |
| `open` | nothing narrows it. Reachable by anyone who finds it. |
| `narrowed` | a security group, ACL or allow-list stands in front |
| `unknown` | something might, and this key could not read it |

`unknown` is never guessed. An unread ACL reported as open is a fabricated
critical finding; reported as narrowed it is a missed one. The map says it could
not tell, and the gap list at the top says why.

## What it looks for

Thirty checks, all about reachability. `mlab-scw catalog --checks` is the whole
catalogue; this command derives the part of it that is about the edge, and says
so at the bottom of every report rather than letting a clean edge read as a
clean account.

| area | the finding that matters most |
| --- | --- |
| Instances | a public address behind a security group whose inbound default is `accept` — which makes every rule under it decoration |
| Security groups | a rule accepting `0.0.0.0/0` on a range that covers SSH, RDP, VNC, PostgreSQL, MySQL, Redis, MongoDB, OpenSearch or the Docker API |
| Elastic Metal | public addresses with no private network: there is no platform firewall in front of a dedicated server |
| Apple silicon | a VNC endpoint on a public address — and the same read call returns the machine's sudo password |
| Addresses | reserved and attached to nothing, in Instances, Flexible IP, load balancers and IPAM |
| Load balancers | a listener on 80 in clear, on 443 with no certificate, with no ACL; certificates expired or expiring inside 30 days |
| Public gateways | an SSH bastion with no allow-list; a port forward publishing an administrative port |
| Kubernetes | a control plane with no allow-list, or one containing `0.0.0.0/0`; node pools whose nodes hold public addresses |
| Managed data | a public endpoint on a database, and an ACL of `0.0.0.0/0` in front of it; Redis without TLS |
| Serverless | `privacy: public` on a container or function: unauthenticated HTTPS |
| Registry | a namespace anyone can pull from |

Two are worth explaining.

**A port forward is judged on both ends.** `2222 → 22` publishes SSH just as
surely as `22 → 22` does, and so does `22 → 2222`. Reading only the public port
misses the first; reading only the private port misses the last.

**An empty ACL list is not the same as an unread one.** A cluster with a
readable, empty allow-list is `k8s.clusters.public-apiserver-no-acl`. A cluster
whose ACLs could not be read produces no finding at all, and appears in the gap
list instead.

## Coverage

```
  ! this map is partial; these were not readable
    redis/clusters: denied in 10 localities
    mnq/sqs-credentials: not activated
```

Gaps are deduplicated by product: a key with no `RedisReadOnly` is refused in
every zone, which is one fact about the key rather than ten facts about the
account.

A product that Scaleway does not run in a locality answers `501 Not
Implemented`, not `404`. That is a correct answer, so it is never retried and
never reported — otherwise every report would carry dozens of lines about
Kafka not existing in `it-mil-1`.

## Narrowing

The sweep covers every region and zone by default, because that is how a cloud
audit avoids a false negative. `--region` and `--zone` narrow it coherently
across global, regional and zonal products — see [Surfaces](Surfaces).

`--concurrency` sets how many requests are in flight; the default of 8 is polite
rather than measured. The client already backs off on 429, so raising it mostly
moves where the waiting happens.

## Permissions

Seventeen read-only permission sets, one per product it reads. Whatever is
missing becomes a gap line rather than an error — the command is built to run
usefully with a narrow key and to say exactly how narrow it was.
