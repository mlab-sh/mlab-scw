//! The public edge: everything that answers from the internet, and what stands
//! in front of it.
//!
//! No single Scaleway endpoint answers "what of mine is reachable". Addresses
//! live in Instances, Elastic Metal, Apple silicon, Flexible IP and IPAM;
//! ports live in load-balancer frontends, gateway PAT rules and database
//! endpoints; and whether any of it is *narrowed* lives in a different call
//! again — security groups, ACL lists, a `privacy` flag. Joined, they are the
//! account's attack surface stated once.
//!
//! The join matters more than any single check in it. An exposure with a tight
//! ACL and one with none look identical in an inventory, and are not the same
//! finding.

use serde_json::Value;

use super::{b, len, n, name_or_id, s, Finding};
use crate::scw::sweep::{items, Fetched};
use crate::scw::Severity;

/// Ports that should never face the internet directly.
const ADMIN_PORTS: [(u32, &str); 9] = [
    (22, "SSH"),
    (3389, "RDP"),
    (5900, "VNC"),
    (5432, "PostgreSQL"),
    (3306, "MySQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (9200, "OpenSearch"),
    (2375, "Docker"),
];

/// A certificate this close to expiry is an outage with a date on it.
const EXPIRING_SOON: i64 = 30 * super::DAY;

/// How narrow the thing in front of an exposure is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Nothing stands in front. Reachable by anyone who finds it.
    Open(String),
    /// Something does, and it is narrowed.
    Narrowed(String),
    /// Something might, and this key could not read it. Never guess here: an
    /// unread ACL reported as "open" is a false finding, and reported as
    /// "narrowed" is a missed one.
    Unknown,
}

impl Control {
    pub fn as_str(&self) -> &str {
        match self {
            Control::Open(what) => what,
            Control::Narrowed(what) => what,
            Control::Unknown => "unreadable",
        }
    }

    pub fn verdict(&self) -> &'static str {
        match self {
            Control::Open(_) => "open",
            Control::Narrowed(_) => "narrowed",
            Control::Unknown => "unknown",
        }
    }
}

/// One thing reachable from the internet.
pub struct Exposed {
    /// What it is, in the words the console uses.
    pub kind: &'static str,
    pub name: String,
    pub locality: String,
    /// The address or hostname it answers on.
    pub endpoint: String,
    /// What is listening, when the API says.
    pub ports: String,
    pub control: Control,
}

impl Exposed {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "kind": self.kind,
            "name": self.name,
            "locality": self.locality,
            "endpoint": self.endpoint,
            "ports": self.ports,
            "control": self.control.as_str(),
            "verdict": self.control.verdict(),
        })
    }
}

/// Everything the edge sweep fetched, with the joins it supports.
pub struct Edge<'a> {
    pub fetched: &'a [Fetched],
}

impl<'a> Edge<'a> {
    pub fn new(fetched: &'a [Fetched]) -> Self {
        Edge { fetched }
    }

    fn of(&self, product: &str, resource: &str) -> Vec<(&'a str, &'a Value)> {
        items(self.fetched, product, resource)
    }

    /// Every exposure, worst verdict first.
    pub fn exposures(&self) -> Vec<Exposed> {
        let mut out = Vec::new();
        self.instances(&mut out);
        self.metal(&mut out);
        self.macs(&mut out);
        self.balancers(&mut out);
        self.gateways(&mut out);
        self.clusters(&mut out);
        self.databases(&mut out);
        self.serverless(&mut out);
        self.registries(&mut out);
        out.sort_by(|a, b| {
            rank(a.control.verdict())
                .cmp(&rank(b.control.verdict()))
                .then_with(|| a.kind.cmp(b.kind))
                .then_with(|| a.name.cmp(&b.name))
        });
        out
    }

    // ---- instances ----------------------------------------------------------

    /// The security group a server sits in, if it was read.
    fn security_group(&self, id: &str) -> Option<&'a Value> {
        self.of("instance", "security-groups")
            .into_iter()
            .map(|(_, v)| v)
            .find(|g| s(g, "id") == id)
    }

    /// Rules of one security group, as fetched in the second round.
    fn rules_of(&self, group_id: &str) -> Vec<&'a Value> {
        self.fetched
            .iter()
            .filter(|f| {
                f.fetch.product == "instance"
                    && f.fetch.resource == "security-group-rules"
                    && f.fetch.path.contains(group_id)
            })
            .flat_map(|f| f.items.iter())
            .collect()
    }

    fn instances(&self, out: &mut Vec<Exposed>) {
        for (zone, srv) in self.of("instance", "servers") {
            let addresses = public_addresses(srv);
            if addresses.is_empty() {
                continue;
            }
            let group = srv.get("security_group");
            let control = match group.map(|g| s(g, "id")).filter(|id| !id.is_empty()) {
                Some(id) => match self.security_group(&id) {
                    Some(g) => self.group_control(g),
                    None => Control::Unknown,
                },
                None => Control::Open("no security group".into()),
            };
            out.push(Exposed {
                kind: "instance",
                name: name_or_id(srv),
                locality: zone.to_string(),
                endpoint: addresses.join(", "),
                ports: String::new(),
                control,
            });
        }
    }

    /// What a security group actually permits, read as its default policy plus
    /// whatever its rules open. The default is the part that matters: a rule
    /// list under `inbound_default_policy: accept` is decoration.
    fn group_control(&self, group: &Value) -> Control {
        let name = name_or_id(group);
        if s(group, "inbound_default_policy") == "accept" {
            return Control::Open(format!("{name}: inbound default accept"));
        }
        let rules = self.rules_of(&s(group, "id"));
        if rules.is_empty() {
            // Not "no rules": the second round may not have run for this group.
            return Control::Narrowed(format!("{name}: inbound default drop"));
        }
        let world: Vec<&&Value> = rules.iter().filter(|r| is_world_accept(r)).collect();
        if world.is_empty() {
            Control::Narrowed(format!(
                "{name}: {} rule(s), none from 0.0.0.0/0",
                rules.len()
            ))
        } else {
            Control::Open(format!(
                "{name}: {} rule(s) accepting 0.0.0.0/0 on {}",
                world.len(),
                world
                    .iter()
                    .map(|r| port_range(r))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    }

    // ---- the machines with no platform firewall -----------------------------

    fn metal(&self, out: &mut Vec<Exposed>) {
        for (zone, srv) in self.of("baremetal", "servers") {
            let addresses: Vec<String> = srv
                .get("ips")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|ip| s(ip, "address"))
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if addresses.is_empty() {
                continue;
            }
            out.push(Exposed {
                kind: "elastic metal",
                name: name_or_id(srv),
                locality: zone.to_string(),
                endpoint: addresses.join(", "),
                ports: String::new(),
                // There is no platform firewall in front of a dedicated server.
                // Whatever the OS does is the whole control, and this API
                // cannot see it.
                control: Control::Open("no platform firewall".into()),
            });
        }
    }

    fn macs(&self, out: &mut Vec<Exposed>) {
        for (zone, srv) in self.of("apple-silicon", "servers") {
            let ip = s(srv, "ip");
            if ip.is_empty() {
                continue;
            }
            let vnc = n(srv, "vnc_port")
                .map(|p| p.to_string())
                .unwrap_or_default();
            out.push(Exposed {
                kind: "apple silicon",
                name: name_or_id(srv),
                locality: zone.to_string(),
                endpoint: ip,
                ports: if vnc.is_empty() {
                    String::new()
                } else {
                    format!("{vnc} (VNC)")
                },
                control: Control::Open("no platform firewall".into()),
            });
        }
    }

    // ---- load balancers -----------------------------------------------------

    fn frontends_of(&self, lb_id: &str) -> Vec<&'a Value> {
        self.fetched
            .iter()
            .filter(|f| {
                f.fetch.product == "lb"
                    && f.fetch.resource == "frontends"
                    && f.fetch.path.contains(lb_id)
            })
            .flat_map(|f| f.items.iter())
            .collect()
    }

    fn balancers(&self, out: &mut Vec<Exposed>) {
        for (zone, lb) in self.of("lb", "lbs") {
            let addresses = lb_addresses(lb);
            if addresses.is_empty() {
                continue;
            }
            let frontends = self.frontends_of(&s(lb, "id"));
            let ports: Vec<String> = frontends
                .iter()
                .filter_map(|f| n(f, "inbound_port").map(|p| p.to_string()))
                .collect();
            out.push(Exposed {
                kind: "load balancer",
                name: name_or_id(lb),
                locality: zone.to_string(),
                endpoint: addresses.join(", "),
                ports: ports.join(", "),
                control: Control::Open(format!("{} frontend(s)", frontends.len())),
            });
        }
    }

    // ---- public gateways ----------------------------------------------------

    fn gateways(&self, out: &mut Vec<Exposed>) {
        for (zone, gw) in self.of("vpc-gw", "gateways") {
            let ip = gw.get("ipv4").map(|v| s(v, "address")).unwrap_or_default();
            if ip.is_empty() {
                continue;
            }
            let pat: Vec<&Value> = self
                .of("vpc-gw", "pat-rules")
                .into_iter()
                .map(|(_, v)| v)
                .filter(|r| s(r, "gateway_id") == s(gw, "id"))
                .collect();
            let mut ports: Vec<String> = pat
                .iter()
                .filter_map(|r| n(r, "public_port").map(|p| p.to_string()))
                .collect();
            let bastion = b(gw, "bastion_enabled");
            if bastion {
                if let Some(p) = n(gw, "bastion_port") {
                    ports.push(format!("{p} (bastion)"));
                }
            }
            let allowed = len(gw, "bastion_allowed_ips");
            let control = if bastion && allowed == 0 {
                Control::Open("SSH bastion open to the internet".into())
            } else if bastion {
                Control::Narrowed(format!("bastion allow-list of {allowed}"))
            } else {
                Control::Narrowed(format!("{} port forward(s)", pat.len()))
            };
            out.push(Exposed {
                kind: "public gateway",
                name: name_or_id(gw),
                locality: zone.to_string(),
                endpoint: ip,
                ports: ports.join(", "),
                control,
            });
        }
    }

    // ---- kubernetes ---------------------------------------------------------

    fn acls_of(&self, cluster_id: &str) -> Vec<&'a Value> {
        self.fetched
            .iter()
            .filter(|f| {
                f.fetch.product == "k8s"
                    && f.fetch.resource == "acls"
                    && f.fetch.path.contains(cluster_id)
            })
            .flat_map(|f| f.items.iter())
            .collect()
    }

    fn clusters(&self, out: &mut Vec<Exposed>) {
        for (region, cl) in self.of("k8s", "clusters") {
            let url = s(cl, "cluster_url");
            if url.is_empty() {
                continue;
            }
            let acls = self.acls_of(&s(cl, "id"));
            let world = acls.iter().any(|a| is_world_cidr(&s(a, "ip")));
            let control = if acls.is_empty() {
                Control::Open("no control-plane allow-list".into())
            } else if world {
                Control::Open(format!("{} ACL(s), one of them 0.0.0.0/0", acls.len()))
            } else {
                Control::Narrowed(format!("{} ACL(s)", acls.len()))
            };
            out.push(Exposed {
                kind: "kubernetes api",
                name: name_or_id(cl),
                locality: region.to_string(),
                endpoint: url,
                ports: "443".into(),
                control,
            });
        }
    }

    // ---- managed data -------------------------------------------------------

    fn rdb_acls_of(&self, instance_id: &str) -> Vec<&'a Value> {
        self.fetched
            .iter()
            .filter(|f| {
                f.fetch.product == "rdb"
                    && f.fetch.resource == "acls"
                    && f.fetch.path.contains(instance_id)
            })
            .flat_map(|f| f.items.iter())
            .collect()
    }

    fn databases(&self, out: &mut Vec<Exposed>) {
        // Managed Database: a public endpoint is one with a load balancer or
        // direct access in front, as opposed to a private network.
        for (region, inst) in self.of("rdb", "instances") {
            for ep in endpoints(inst) {
                if !rdb_endpoint_is_public(ep) {
                    continue;
                }
                let acls = self.rdb_acls_of(&s(inst, "id"));
                let world = acls.iter().any(|a| is_world_cidr(&s(a, "ip")));
                let control = if acls.is_empty() {
                    Control::Open("no ACL".into())
                } else if world {
                    Control::Open(format!("{} ACL(s), one of them 0.0.0.0/0", acls.len()))
                } else {
                    Control::Narrowed(format!("{} ACL(s)", acls.len()))
                };
                out.push(Exposed {
                    kind: "managed database",
                    name: name_or_id(inst),
                    locality: region.to_string(),
                    endpoint: endpoint_host(ep),
                    ports: n(ep, "port").map(|p| p.to_string()).unwrap_or_default(),
                    control,
                });
            }
        }

        for (zone, cl) in self.of("redis", "clusters") {
            for ep in endpoints(cl) {
                if ep.get("public_network").is_none() {
                    continue;
                }
                let acls = cl
                    .get("acl_rules")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let world = acls.iter().any(|a| is_world_cidr(&s(a, "ip_cidr")));
                let control = if acls.is_empty() {
                    Control::Open("no ACL".into())
                } else if world {
                    Control::Open(format!("{} ACL(s), one of them 0.0.0.0/0", acls.len()))
                } else {
                    Control::Narrowed(format!("{} ACL(s)", acls.len()))
                };
                out.push(Exposed {
                    kind: "redis",
                    name: name_or_id(cl),
                    locality: zone.to_string(),
                    endpoint: endpoint_host(ep),
                    ports: n(ep, "port").map(|p| p.to_string()).unwrap_or_default(),
                    control,
                });
            }
        }

        for (product, kind) in [
            ("mongodb", "mongodb"),
            ("kafka", "kafka"),
            ("searchdb", "opensearch"),
        ] {
            let resource = if product == "searchdb" {
                "deployments"
            } else if product == "kafka" {
                "clusters"
            } else {
                "instances"
            };
            for (region, thing) in self.of(product, resource) {
                for ep in endpoints(thing) {
                    if ep.get("public_network").is_none() && !b(ep, "public") {
                        continue;
                    }
                    out.push(Exposed {
                        kind,
                        name: name_or_id(thing),
                        locality: region.to_string(),
                        endpoint: endpoint_host(ep),
                        ports: n(ep, "port").map(|p| p.to_string()).unwrap_or_default(),
                        control: Control::Open("public endpoint".into()),
                    });
                }
            }
        }
    }

    // ---- serverless ---------------------------------------------------------

    fn serverless(&self, out: &mut Vec<Exposed>) {
        for (product, resource, kind) in [
            ("containers", "containers", "container"),
            ("functions", "functions", "function"),
        ] {
            for (region, thing) in self.of(product, resource) {
                if s(thing, "privacy") != "public" {
                    continue;
                }
                out.push(Exposed {
                    kind,
                    name: name_or_id(thing),
                    locality: region.to_string(),
                    endpoint: s(thing, "domain_name"),
                    ports: "443".into(),
                    control: Control::Open("privacy: public, no token required".into()),
                });
            }
        }

        for (region, dep) in self.of("inference", "deployments") {
            for ep in endpoints(dep) {
                if ep.get("public_network").is_none() {
                    continue;
                }
                let control = if b(ep, "disable_auth") {
                    Control::Open("authentication disabled".into())
                } else {
                    Control::Narrowed("bearer token required".into())
                };
                out.push(Exposed {
                    kind: "inference",
                    name: name_or_id(dep),
                    locality: region.to_string(),
                    endpoint: s(ep, "url"),
                    ports: "443".into(),
                    control,
                });
            }
        }
    }

    fn registries(&self, out: &mut Vec<Exposed>) {
        for (region, ns) in self.of("registry", "namespaces") {
            if !b(ns, "is_public") {
                continue;
            }
            out.push(Exposed {
                kind: "registry",
                name: name_or_id(ns),
                locality: region.to_string(),
                endpoint: s(ns, "endpoint"),
                ports: "443".into(),
                control: Control::Open("anonymous pull".into()),
            });
        }
    }
}

/// Every check id this module can emit.
pub const IMPLEMENTED: [&str; 34] = [
    "instance.servers.public-no-filter",
    "instance.servers.default-group",
    "instance.security-groups.inbound-accept",
    "instance.security-group-rules.world-ssh",
    "instance.security-group-rules.world-any",
    "instance.ips.dangling",
    "baremetal.servers.no-private-network",
    "baremetal.servers.rescue",
    "apple-silicon.servers.vnc",
    "flexible-ip.fips.dangling",
    "ipam.ips.public-inventory",
    "ipam.ips.unattached",
    "lb.frontends.plain-http",
    "lb.frontends.no-certificate",
    "lb.acls.none",
    "lb.certificates.expired",
    "lb.certificates.expiring",
    "lb.ips.dangling",
    "vpc-gw.gateways.bastion-open",
    "vpc-gw.pat-rules.admin-port",
    "k8s.clusters.public-apiserver-no-acl",
    "k8s.acls.world",
    "k8s.pools.public-nodes",
    "rdb.instances.public-endpoint",
    "rdb.acls.world",
    "redis.clusters.public-no-acl",
    "redis.clusters.no-tls",
    "containers.containers.public",
    "registry.namespaces.public",
    "mongodb.instances.public-endpoint",
    "kafka.clusters.public",
    "searchdb.deployments.public",
    "inference.deployments.no-auth",
    "functions.functions.public",
];

impl Edge<'_> {
    /// Every finding the edge supports. Pure over what was fetched.
    pub fn audit(&self, now: i64) -> Vec<Finding> {
        let mut f = Vec::new();
        self.check_instances(&mut f);
        self.check_metal(&mut f);
        self.check_addresses(&mut f);
        self.check_balancers(&mut f);
        self.check_certificates(now, &mut f);
        self.check_gateways(&mut f);
        self.check_kubernetes(&mut f);
        self.check_data(&mut f);
        self.check_serverless(&mut f);
        self.check_open_by_nature(&mut f);
        super::sort(&mut f);
        f
    }

    fn check_instances(&self, out: &mut Vec<Finding>) {
        for (zone, srv) in self.of("instance", "servers") {
            let addresses = public_addresses(srv);
            if addresses.is_empty() {
                continue;
            }
            let who = format!("{} ({zone})", name_or_id(srv));
            let group_id = srv
                .get("security_group")
                .map(|g| s(g, "id"))
                .unwrap_or_default();
            let group = self.security_group(&group_id);

            if let Some(g) = group {
                if matches!(self.group_control(g), Control::Open(_)) {
                    out.push(Finding::new(
                        "instance.servers.public-no-filter",
                        Severity::Critical,
                        &who,
                        format!(
                            "{} reachable behind {}",
                            addresses.join(", "),
                            self.group_control(g).as_str()
                        ),
                    ));
                }
                if b(g, "project_default") || b(g, "organization_default") {
                    out.push(Finding::new(
                        "instance.servers.default-group",
                        Severity::High,
                        &who,
                        "in the project's default security group, which is shared with every \
                         other machine and changes for all of them at once",
                    ));
                }
            }
        }

        for (zone, g) in self.of("instance", "security-groups") {
            let who = format!("{} ({zone})", name_or_id(g));
            if s(g, "inbound_default_policy") == "accept" {
                out.push(Finding::new(
                    "instance.security-groups.inbound-accept",
                    Severity::Critical,
                    &who,
                    format!(
                        "inbound default is accept, which makes the {} rule(s) below it \
                         decoration",
                        len(g, "rules")
                    ),
                ));
            }
            for r in self.rules_of(&s(g, "id")) {
                if !is_world_accept(r) {
                    continue;
                }
                let admin = covers_admin_port(r);
                if admin.is_empty() {
                    out.push(Finding::new(
                        "instance.security-group-rules.world-any",
                        Severity::High,
                        &who,
                        format!("accepts 0.0.0.0/0 on {}", port_range(r)),
                    ));
                } else {
                    out.push(Finding::new(
                        "instance.security-group-rules.world-ssh",
                        Severity::Critical,
                        &who,
                        format!(
                            "accepts 0.0.0.0/0 on {} — that range covers {}",
                            port_range(r),
                            admin.join(", ")
                        ),
                    ));
                }
            }
        }
    }

    /// Whether a dedicated server is attached to any private network.
    ///
    /// Attachments are a separate listing, so an unread one has to read as
    /// unknown rather than as absent: reporting "no private network" because
    /// the key could not see the attachments would be a fabricated finding.
    fn metal_attachments(&self, zone: &str) -> Option<usize> {
        let read = self.fetched.iter().any(|f| {
            f.fetch.product == "baremetal"
                && f.fetch.resource == "server-private-networks"
                && f.fetch.locality == zone
                && f.gap.is_none()
        });
        read.then(|| {
            self.of("baremetal", "server-private-networks")
                .into_iter()
                .filter(|(l, _)| *l == zone)
                .count()
        })
    }

    fn check_metal(&self, out: &mut Vec<Finding>) {
        for (zone, srv) in self.of("baremetal", "servers") {
            let who = format!("{} ({zone})", name_or_id(srv));
            let addresses: Vec<String> = srv
                .get("ips")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|ip| s(ip, "address"))
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            if !addresses.is_empty() && self.metal_attachments(zone) == Some(0) {
                out.push(Finding::new(
                    "baremetal.servers.no-private-network",
                    Severity::High,
                    &who,
                    format!(
                        "reachable on {} with no private network attached: there is no platform \
                         firewall in front of a dedicated server, so its own is the only one",
                        addresses.join(", ")
                    ),
                ));
            }
            if srv.get("rescue_server").is_some_and(|v| !v.is_null()) {
                out.push(Finding::new(
                    "baremetal.servers.rescue",
                    Severity::Critical,
                    &who,
                    "left in rescue mode, which is a root shell reachable with a password this \
                     API will hand to anything holding ElasticMetalReadOnly",
                ));
            }
        }

        for (zone, srv) in self.of("apple-silicon", "servers") {
            if s(srv, "ip").is_empty() || s(srv, "vnc_url").is_empty() {
                continue;
            }
            out.push(Finding::new(
                "apple-silicon.servers.vnc",
                Severity::Critical,
                format!("{} ({zone})", name_or_id(srv)),
                format!(
                    "a VNC endpoint on the public address {} — and the same read call returns \
                     the machine's sudo password",
                    s(srv, "ip")
                ),
            ));
        }
    }

    fn check_addresses(&self, out: &mut Vec<Finding>) {
        for (zone, ip) in self.of("instance", "ips") {
            if ip.get("server").is_some_and(|v| !v.is_null()) {
                continue;
            }
            out.push(Finding::new(
                "instance.ips.dangling",
                Severity::High,
                format!("{} ({zone})", s(ip, "address")),
                "reserved and attached to nothing: still billed, and still the target of any \
                 DNS record that was left pointing at it",
            ));
        }

        for (zone, fip) in self.of("flexible-ip", "fips") {
            if !s(fip, "server_id").is_empty() {
                continue;
            }
            out.push(Finding::new(
                "flexible-ip.fips.dangling",
                Severity::High,
                format!("{} ({zone})", s(fip, "ip_address")),
                "detached, and whatever it was serving is either gone or moved",
            ));
        }

        let ipam = self.of("ipam", "ips");
        let public: Vec<&(&str, &Value)> = ipam
            .iter()
            .filter(|(_, ip)| {
                ip.get("source")
                    .is_some_and(|src| src.get("zonal").is_some())
            })
            .collect();
        if !public.is_empty() {
            out.push(Finding::new(
                "ipam.ips.public-inventory",
                Severity::High,
                format!("{} address(es)", public.len()),
                "the account's publicly routable addresses, as IPAM knows them — the one list \
                 no per-product view can produce",
            ));
        }
        let unattached = ipam
            .iter()
            .filter(|(_, ip)| ip.get("resource").is_none_or(Value::is_null))
            .count();
        if unattached > 0 {
            out.push(Finding::new(
                "ipam.ips.unattached",
                Severity::Medium,
                format!("{unattached} address(es)"),
                "held by nothing",
            ));
        }
    }

    fn check_balancers(&self, out: &mut Vec<Finding>) {
        for (zone, lb) in self.of("lb", "lbs") {
            let who = format!("{} ({zone})", name_or_id(lb));
            for fe in self.frontends_of(&s(lb, "id")) {
                let port = n(fe, "inbound_port").unwrap_or(0);
                let has_cert = fe.get("certificate").is_some_and(|c| !c.is_null())
                    || len(fe, "certificate_ids") > 0;
                if port == 80 {
                    out.push(Finding::new(
                        "lb.frontends.plain-http",
                        Severity::High,
                        &who,
                        format!("{} listens on 80 in clear", name_or_id(fe)),
                    ));
                }
                if port == 443 && !has_cert {
                    out.push(Finding::new(
                        "lb.frontends.no-certificate",
                        Severity::High,
                        &who,
                        format!(
                            "{} listens on 443 with no certificate attached",
                            name_or_id(fe)
                        ),
                    ));
                }
                if self.acls_of_frontend(&s(fe, "id")).is_empty() && port != 80 {
                    out.push(Finding::new(
                        "lb.acls.none",
                        Severity::Medium,
                        &who,
                        format!(
                            "{} has no ACL: every source address reaches the backends behind it",
                            name_or_id(fe)
                        ),
                    ));
                }
            }
        }

        for (zone, ip) in self.of("lb", "ips") {
            if !s(ip, "lb_id").is_empty() || ip.get("lb").is_some_and(|v| !v.is_null()) {
                continue;
            }
            out.push(Finding::new(
                "lb.ips.dangling",
                Severity::Medium,
                format!("{} ({zone})", s(ip, "ip_address")),
                "reserved, attached to no load balancer, and still billed",
            ));
        }
    }

    fn certificates_of(&self, lb_id: &str) -> Vec<&Value> {
        self.fetched
            .iter()
            .filter(|f| {
                f.fetch.product == "lb"
                    && f.fetch.resource == "certificates"
                    && f.fetch.path.contains(lb_id)
            })
            .flat_map(|f| f.items.iter())
            .collect()
    }

    fn check_certificates(&self, now: i64, out: &mut Vec<Finding>) {
        for (zone, lb) in self.of("lb", "lbs") {
            for cert in self.certificates_of(&s(lb, "id")) {
                let Some(expiry) = crate::scw::epoch_of(&s(cert, "not_valid_after")) else {
                    continue;
                };
                let who = format!("{} on {} ({zone})", name_or_id(cert), name_or_id(lb));
                let left = expiry - now;
                if left <= 0 {
                    out.push(Finding::new(
                        "lb.certificates.expired",
                        Severity::Critical,
                        who,
                        format!("expired {}", crate::scw::relative(-left)),
                    ));
                } else if left <= EXPIRING_SOON {
                    out.push(Finding::new(
                        "lb.certificates.expiring",
                        Severity::High,
                        who,
                        format!("expires {}", crate::scw::relative(-left)),
                    ));
                }
            }
        }
    }

    fn acls_of_frontend(&self, frontend_id: &str) -> Vec<&Value> {
        self.fetched
            .iter()
            .filter(|f| {
                f.fetch.product == "lb"
                    && f.fetch.resource == "acls"
                    && f.fetch.path.contains(frontend_id)
            })
            .flat_map(|f| f.items.iter())
            .collect()
    }

    fn check_gateways(&self, out: &mut Vec<Finding>) {
        for (zone, gw) in self.of("vpc-gw", "gateways") {
            let who = format!("{} ({zone})", name_or_id(gw));
            if b(gw, "bastion_enabled") && len(gw, "bastion_allowed_ips") == 0 {
                out.push(Finding::new(
                    "vpc-gw.gateways.bastion-open",
                    Severity::Critical,
                    &who,
                    format!(
                        "the SSH bastion is on with no allow-list, on port {}: a jump host into \
                         the private network, reachable from anywhere",
                        n(gw, "bastion_port").unwrap_or(61000)
                    ),
                ));
            }
        }

        for (zone, r) in self.of("vpc-gw", "pat-rules") {
            let private = n(r, "private_port").unwrap_or(0);
            let public = n(r, "public_port").unwrap_or(0);
            let Some(service) = admin_service(private).or_else(|| admin_service(public)) else {
                continue;
            };
            out.push(Finding::new(
                "vpc-gw.pat-rules.admin-port",
                Severity::Critical,
                format!("{}:{public} ({zone})", s(r, "private_ip")),
                format!(
                    "forwards the internet to {service} on {}:{private}",
                    s(r, "private_ip")
                ),
            ));
        }
    }

    fn check_kubernetes(&self, out: &mut Vec<Finding>) {
        for (region, cl) in self.of("k8s", "clusters") {
            let who = format!("{} ({region})", name_or_id(cl));
            if s(cl, "cluster_url").is_empty() {
                continue;
            }
            let acls = self.acls_of(&s(cl, "id"));
            if acls.is_empty() {
                out.push(Finding::new(
                    "k8s.clusters.public-apiserver-no-acl",
                    Severity::Critical,
                    &who,
                    "the control plane answers on the public internet with no allow-list in \
                     front of it",
                ));
            }
            for a in &acls {
                if is_world_cidr(&s(a, "ip")) {
                    out.push(Finding::new(
                        "k8s.acls.world",
                        Severity::Critical,
                        &who,
                        "0.0.0.0/0 in the control-plane allow-list, which is the same as having \
                         none",
                    ));
                }
            }
        }

        for (region, pool) in self.of("k8s", "pools") {
            if b(pool, "public_ip_disabled") {
                continue;
            }
            out.push(Finding::new(
                "k8s.pools.public-nodes",
                Severity::High,
                format!("{} ({region})", name_or_id(pool)),
                "every node in this pool holds a public address, so its kubelet and any \
                 NodePort service are internet-facing",
            ));
        }
    }

    fn check_data(&self, out: &mut Vec<Finding>) {
        for (region, inst) in self.of("rdb", "instances") {
            let who = format!("{} ({region})", name_or_id(inst));
            if !endpoints(inst).iter().any(|ep| rdb_endpoint_is_public(ep)) {
                continue;
            }
            out.push(Finding::new(
                "rdb.instances.public-endpoint",
                Severity::Critical,
                &who,
                "a public endpoint, which is the default and stays the default",
            ));
            for a in self.rdb_acls_of(&s(inst, "id")) {
                if is_world_cidr(&s(a, "ip")) {
                    out.push(Finding::new(
                        "rdb.acls.world",
                        Severity::Critical,
                        &who,
                        "0.0.0.0/0 in the ACL: the database is on the internet with a password \
                         as its only control",
                    ));
                }
            }
        }

        for (zone, cl) in self.of("redis", "clusters") {
            let who = format!("{} ({zone})", name_or_id(cl));
            let public = endpoints(cl)
                .iter()
                .any(|ep| ep.get("public_network").is_some());
            if public {
                let world = cl
                    .get("acl_rules")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().any(|r| is_world_cidr(&s(r, "ip_cidr"))));
                let none = cl
                    .get("acl_rules")
                    .and_then(Value::as_array)
                    .is_none_or(|a| a.is_empty());
                if world || none {
                    out.push(Finding::new(
                        "redis.clusters.public-no-acl",
                        Severity::Critical,
                        &who,
                        "a public endpoint with no narrowing ACL",
                    ));
                }
            }
            if !b(cl, "tls_enabled") {
                out.push(Finding::new(
                    "redis.clusters.no-tls",
                    Severity::Critical,
                    &who,
                    "TLS is off: the password and every value cross the network in clear",
                ));
            }
        }
    }

    /// The products whose exposure is the finding: there is no ACL to read and
    /// no control to weigh, so a public endpoint is the whole story.
    ///
    /// These built rows in the map for a while without emitting anything, which
    /// meant a public MongoDB appeared in the inventory and not in the
    /// findings. A map is read by whoever asked for one; a finding list is read
    /// by everyone.
    fn check_open_by_nature(&self, out: &mut Vec<Finding>) {
        for (region, ns) in self.of("registry", "namespaces") {
            if !b(ns, "is_public") {
                continue;
            }
            out.push(Finding::new(
                "registry.namespaces.public",
                Severity::Critical,
                format!("{} ({region})", name_or_id(ns)),
                format!(
                    "anonymous pull at {}: every image in it, every layer, and anything baked \
                     into them",
                    s(ns, "endpoint")
                ),
            ));
        }

        for (product, resource, id, what) in [
            (
                "mongodb",
                "instances",
                "mongodb.instances.public-endpoint",
                "MongoDB",
            ),
            ("kafka", "clusters", "kafka.clusters.public", "Kafka"),
            (
                "searchdb",
                "deployments",
                "searchdb.deployments.public",
                "OpenSearch",
            ),
        ] {
            for (locality, thing) in self.of(product, resource) {
                let public: Vec<&Value> = endpoints(thing)
                    .into_iter()
                    .filter(|ep| ep.get("public_network").is_some() || b(ep, "public"))
                    .collect();
                if public.is_empty() {
                    continue;
                }
                out.push(Finding::new(
                    id,
                    Severity::Critical,
                    format!("{} ({locality})", name_or_id(thing)),
                    format!(
                        "{what} answers on the public internet at {}",
                        public
                            .iter()
                            .map(|ep| endpoint_host(ep))
                            .filter(|h| !h.is_empty())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        }

        for (region, dep) in self.of("inference", "deployments") {
            for ep in endpoints(dep) {
                if ep.get("public_network").is_none() || !b(ep, "disable_auth") {
                    continue;
                }
                out.push(Finding::new(
                    "inference.deployments.no-auth",
                    Severity::Critical,
                    format!("{} ({region})", name_or_id(dep)),
                    format!(
                        "a public model endpoint at {} with authentication disabled: a GPU \
                         anyone can drive, billed to you",
                        s(ep, "url")
                    ),
                ));
            }
        }
    }

    fn check_serverless(&self, out: &mut Vec<Finding>) {
        for (product, resource, id) in [
            ("containers", "containers", "containers.containers.public"),
            ("functions", "functions", "functions.functions.public"),
        ] {
            for (region, thing) in self.of(product, resource) {
                if s(thing, "privacy") != "public" {
                    continue;
                }
                out.push(Finding::new(
                    id,
                    Severity::Critical,
                    format!("{} ({region})", name_or_id(thing)),
                    format!(
                        "unauthenticated HTTPS at {}: anyone who finds the name can invoke it",
                        s(thing, "domain_name")
                    ),
                ));
            }
        }
    }
}

fn rank(verdict: &str) -> u8 {
    match verdict {
        "open" => 0,
        "unknown" => 1,
        _ => 2,
    }
}

// ---- shared readers ---------------------------------------------------------

fn endpoints(v: &Value) -> Vec<&Value> {
    v.get("endpoints")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

/// The host an endpoint answers on, whichever field it uses to say so.
fn endpoint_host(ep: &Value) -> String {
    for key in ["hostname", "dns_record", "url", "ip"] {
        let found = s(ep, key);
        if !found.is_empty() {
            return found;
        }
    }
    // Redis and Kafka list addresses rather than one.
    for key in ["ips", "dns_records"] {
        if let Some(a) = ep.get(key).and_then(Value::as_array) {
            let joined: Vec<String> = a
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| s(x, "address"))
                })
                .filter(|x| !x.is_empty())
                .collect();
            if !joined.is_empty() {
                return joined.join(", ");
            }
        }
    }
    String::new()
}

/// A Managed Database endpoint faces the internet when it is fronted by a load
/// balancer or by direct access, rather than attached to a private network.
fn rdb_endpoint_is_public(ep: &Value) -> bool {
    ep.get("private_network").is_none()
        && (ep.get("load_balancer").is_some() || ep.get("direct_access").is_some())
}

/// Every public address on an Instance, across both the old single field and
/// the current list.
fn public_addresses(server: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ip) = server.get("public_ip") {
        let a = s(ip, "address");
        if !a.is_empty() {
            out.push(a);
        }
    }
    if let Some(list) = server.get("public_ips").and_then(Value::as_array) {
        for ip in list {
            let a = s(ip, "address");
            if !a.is_empty() && !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

fn lb_addresses(lb: &Value) -> Vec<String> {
    lb.get("ip")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|ip| s(ip, "ip_address"))
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a CIDR means "anywhere".
fn is_world_cidr(cidr: &str) -> bool {
    matches!(cidr.trim(), "0.0.0.0/0" | "::/0" | "0.0.0.0" | "*")
}

fn is_world_accept(rule: &Value) -> bool {
    s(rule, "direction") == "inbound"
        && s(rule, "action") == "accept"
        && is_world_cidr(&s(rule, "ip_range"))
}

/// A rule's port range, as something a person reads.
fn port_range(rule: &Value) -> String {
    match (n(rule, "dest_port_from"), n(rule, "dest_port_to")) {
        (Some(a), Some(bb)) if a == bb => a.to_string(),
        (Some(a), Some(bb)) => format!("{a}-{bb}"),
        (Some(a), None) => a.to_string(),
        _ => "all ports".to_string(),
    }
}

/// The administrative service on a port, if it is one.
fn admin_service(port: i64) -> Option<&'static str> {
    ADMIN_PORTS
        .iter()
        .find(|(p, _)| *p as i64 == port)
        .map(|(_, name)| *name)
}

/// Whether a rule's range covers an administrative port.
fn covers_admin_port(rule: &Value) -> Vec<&'static str> {
    let (from, to) = (n(rule, "dest_port_from"), n(rule, "dest_port_to"));
    match (from, to) {
        (None, None) => ADMIN_PORTS.iter().map(|(_, n)| *n).collect(),
        (Some(a), b) => {
            let end = b.unwrap_or(a);
            ADMIN_PORTS
                .iter()
                .filter(|(p, _)| (a..=end).contains(&(*p as i64)))
                .map(|(_, n)| *n)
                .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
