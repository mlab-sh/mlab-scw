//! The quiet products: what nobody looks at.
//!
//! Nothing in an account's daily operation surfaces any of this. A registry
//! namespace's visibility, a credential pasted into an environment variable, a
//! DNS record pointing at an address that was released last year, a device
//! fleet configured to trust anything that connects — none of it appears on a
//! dashboard, none of it pages anybody, and all of it stays true for years.
//!
//! Which is why it is where the surprising findings are.

use std::collections::BTreeSet;

use serde_json::Value;

use super::{age_secs, b, credential, len, n, name_or_id, s, Finding, DAY};
use crate::scw::sweep::{items, Fetched};
use crate::scw::Severity;

const STALE_IMAGE: i64 = 365 * DAY;
const ANCIENT_SNAPSHOT: i64 = 365 * DAY;
const NEVER_ROTATED: i64 = 365 * DAY;
const DORMANT_DEVICE: i64 = 90 * DAY;
const IDLE_RUNNER: i64 = 30 * DAY;
const DOMAIN_EXPIRING: i64 = 30 * DAY;
const LONG_TTL: i64 = 86_400;

/// Every check id this module can emit.
pub const IMPLEMENTED: [&str; 47] = [
    "containers.namespaces.plaintext-secret",
    "containers.containers.plaintext-secret",
    "containers.containers.http-redirected-off",
    "containers.containers.v1-sandbox",
    "functions.namespaces.plaintext-secret",
    "functions.functions.plaintext-secret",
    "functions.functions.http-redirected-off",
    "jobs.job-definitions.plaintext-secret",
    "jobs.job-definitions.foreign-image",
    "registry.images.public",
    "registry.namespaces.empty",
    "domain.domains.expiring",
    "domain.domains.no-dnssec",
    "domain.domains.external",
    "domain.records.dangling-cname",
    "domain.records.spf-weak",
    "domain.records.dmarc-none",
    "domain.records.no-caa",
    "domain.records.wildcard",
    "domain.records.long-ttl",
    "domain.ssl-certificates.private-key-readable",
    "iot.hubs.auto-provisioning",
    "iot.hubs.no-custom-ca",
    "iot.hubs.events-disabled",
    "iot.devices.allow-insecure",
    "iot.devices.shared-identity",
    "iot.devices.dormant",
    "iot.routes.foreign-endpoint",
    "apple-silicon.servers.sudo-password",
    "apple-silicon.servers.idle",
    "secret-manager.secrets.never-rotated",
    "secret-manager.secrets.unprotected",
    "secret-manager.secrets.unused",
    "secret-manager.secrets.no-key",
    "key-manager.keys.no-rotation",
    "key-manager.keys.unprotected",
    "key-manager.keys.unused",
    "mnq.sqs-credentials.can-manage",
    "mnq.sns-credentials.can-manage",
    "tem.domains.unverified-active",
    "tem.domains.reputation",
    "instance.images.public",
    "instance.images.stale",
    "instance.volumes.orphan",
    "instance.snapshots.ancient",
    "block.snapshots.ancient",
    "file.filesystems.unattached",
];

pub struct Quiet<'a> {
    pub fetched: &'a [Fetched],
    /// The account's own organization.
    ///
    /// Needed because one listing does not only return the account's own
    /// things: `instance/images` includes Scaleway's entire marketplace, some
    /// twenty-three thousand images, every one of them `public: true`. Without
    /// an owner to compare against, "a public custom image" is a finding about
    /// AlmaLinux.
    pub organization: String,
}

impl<'a> Quiet<'a> {
    pub fn new(fetched: &'a [Fetched], organization: &str) -> Self {
        Quiet {
            fetched,
            organization: organization.to_string(),
        }
    }

    /// Whether a thing belongs to the account being audited.
    ///
    /// With no organization to compare against this answers `false`: judging
    /// somebody else's resources is worse than judging none.
    fn ours(&self, thing: &Value) -> bool {
        !self.organization.is_empty()
            && (s(thing, "organization") == self.organization
                || s(thing, "organization_id") == self.organization)
    }

    fn of(&self, product: &str, resource: &str) -> Vec<(&'a str, &'a Value)> {
        items(self.fetched, product, resource)
    }

    pub fn audit(&self, now: i64) -> Vec<Finding> {
        let mut f = Vec::new();
        self.serverless(&mut f);
        self.registry(&mut f);
        self.dns(now, &mut f);
        self.iot(now, &mut f);
        self.macs(now, &mut f);
        self.vaults(now, &mut f);
        self.queues(&mut f);
        self.mail(&mut f);
        self.leftovers(now, &mut f);
        super::sort(&mut f);
        f
    }

    // ---- credentials pasted where they can be read --------------------------

    /// Report every plaintext credential in one environment map.
    ///
    /// `secret_environment_variables` is the field Scaleway masks; the plain
    /// one is returned in full to anything holding the read-only permission
    /// set, which is what makes this the highest-value check in the catalogue.
    fn env(&self, id: &'static str, who: &str, thing: &Value, out: &mut Vec<Finding>) {
        let leaks = credential::inspect_all(&thing["environment_variables"]);
        if leaks.is_empty() {
            return;
        }
        let certain = leaks.iter().filter(|l| l.certain).count();
        out.push(Finding::new(
            id,
            Severity::Critical,
            who,
            format!(
                "{} in environment_variables rather than secret_environment_variables, so a \
                 read-only key receives {}: {}",
                if certain > 0 {
                    format!("{certain} credential(s)")
                } else {
                    format!("{} likely credential(s)", leaks.len())
                },
                if leaks.len() == 1 { "it" } else { "them" },
                leaks
                    .iter()
                    .map(|l| format!("{} ({})", l.name, l.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        ));
    }

    fn serverless(&self, out: &mut Vec<Finding>) {
        for (product, resource, id) in [
            (
                "containers",
                "namespaces",
                "containers.namespaces.plaintext-secret",
            ),
            (
                "containers",
                "containers",
                "containers.containers.plaintext-secret",
            ),
            (
                "functions",
                "namespaces",
                "functions.namespaces.plaintext-secret",
            ),
            (
                "functions",
                "functions",
                "functions.functions.plaintext-secret",
            ),
            (
                "jobs",
                "job-definitions",
                "jobs.job-definitions.plaintext-secret",
            ),
        ] {
            for (region, thing) in self.of(product, resource) {
                self.env(id, &format!("{} ({region})", name_or_id(thing)), thing, out);
            }
        }

        for (product, resource, id) in [
            (
                "containers",
                "containers",
                "containers.containers.http-redirected-off",
            ),
            (
                "functions",
                "functions",
                "functions.functions.http-redirected-off",
            ),
        ] {
            for (region, thing) in self.of(product, resource) {
                if s(thing, "http_option") == "enabled" {
                    out.push(Finding::new(
                        id,
                        Severity::High,
                        format!("{} ({region})", name_or_id(thing)),
                        "http_option allows plain HTTP, so a client that forgets the scheme is \
                         not corrected — it is served",
                    ));
                }
            }
        }

        for (region, c) in self.of("containers", "containers") {
            if s(c, "sandbox") == "v1" {
                out.push(Finding::new(
                    "containers.containers.v1-sandbox",
                    Severity::Medium,
                    format!("{} ({region})", name_or_id(c)),
                    "sandbox v1, the weaker isolation mode",
                ));
            }
        }

        for (region, j) in self.of("jobs", "job-definitions") {
            let image = s(j, "image_uri");
            if image.is_empty() || image.contains("rg.") && image.contains("scw.cloud") {
                continue;
            }
            out.push(Finding::new(
                "jobs.job-definitions.foreign-image",
                Severity::Medium,
                format!("{} ({region})", name_or_id(j)),
                format!(
                    "runs {image}, which is not in your own registry: what it contains is \
                         somebody else's decision, on every run"
                ),
            ));
        }
    }

    // ---- registry -----------------------------------------------------------

    fn registry(&self, out: &mut Vec<Finding>) {
        for (region, img) in self.of("registry", "images") {
            if s(img, "visibility") != "public" {
                continue;
            }
            out.push(Finding::new(
                "registry.images.public",
                Severity::Critical,
                format!("{} ({region})", name_or_id(img)),
                "visibility is public: every layer, and everything baked into them, pullable \
                 anonymously",
            ));
        }
        for (region, ns) in self.of("registry", "namespaces") {
            if n(ns, "image_count") == Some(0) {
                out.push(Finding::new(
                    "registry.namespaces.empty",
                    Severity::Low,
                    format!("{} ({region})", name_or_id(ns)),
                    "no images, and a name nobody will remember reserving",
                ));
            }
        }
    }

    // ---- names --------------------------------------------------------------

    /// Every address and platform hostname this account currently holds.
    ///
    /// The set a DNS record has to be checked against: a name pointing at
    /// something in it is fine, and a name pointing at a Scaleway thing that is
    /// *not* in it is a name somebody else can claim.
    fn held(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (product, resource, field) in [
            ("instance", "ips", "address"),
            ("flexible-ip", "fips", "ip_address"),
            ("lb", "ips", "ip_address"),
            ("containers", "containers", "domain_name"),
            ("functions", "functions", "domain_name"),
            ("registry", "namespaces", "endpoint"),
            ("k8s", "clusters", "dns_wildcard"),
        ] {
            for (_, thing) in self.of(product, resource) {
                let v = s(thing, field);
                if !v.is_empty() {
                    out.insert(v.trim_end_matches('.').to_ascii_lowercase());
                }
            }
        }
        for (_, cl) in self.of("k8s", "clusters") {
            let url = s(cl, "cluster_url");
            if let Some(host) = url.strip_prefix("https://") {
                out.insert(host.trim_end_matches('/').to_ascii_lowercase());
            }
        }
        for (_, ip) in self.of("ipam", "ips") {
            let a = s(ip, "address");
            if let Some((addr, _)) = a.split_once('/') {
                out.insert(addr.to_string());
            }
        }
        out
    }

    fn dns(&self, now: i64, out: &mut Vec<Finding>) {
        for (_, d) in self.of("domain", "domains") {
            let who = s(d, "domain");
            if let Some(age) = age_secs(d, "expired_at", now) {
                // `expired_at` is the expiry date, so a negative age is time left.
                let left = -age;
                if left > 0 && left < DOMAIN_EXPIRING && s(d, "auto_renew_status") != "enabled" {
                    out.push(Finding::new(
                        "domain.domains.expiring",
                        Severity::Critical,
                        &who,
                        format!(
                            "expires {} and auto-renew is not on: everything named under it \
                             depends on a payment nobody is watching",
                            crate::scw::relative(age)
                        ),
                    ));
                }
            }
            if s(d, "dnssec") != "enabled" {
                out.push(Finding::new(
                    "domain.domains.no-dnssec",
                    Severity::High,
                    &who,
                    "DNSSEC is off, so a resolver cannot tell your answers from someone else's",
                ));
            }
            if b(d, "is_external") {
                out.push(Finding::new(
                    "domain.domains.external",
                    Severity::Medium,
                    &who,
                    "registered elsewhere and served here, so two parties can change what it \
                     means and neither sees the other",
                ));
            }
        }

        if !self.of("domain", "ssl-certificates").is_empty() {
            out.push(Finding::new(
                "domain.ssl-certificates.private-key-readable",
                Severity::Critical,
                format!(
                    "{} certificate(s)",
                    self.of("domain", "ssl-certificates").len()
                ),
                "this listing returns `private_key` in full, so DomainsDNSReadOnly is the \
                 ability to impersonate the sites it covers — drop that permission set unless \
                 the account needs it",
            ));
        }

        let held = self.held();
        for (_, zone) in self.of("domain", "dns-zones") {
            let zone_name = format!("{}.{}", s(zone, "subdomain"), s(zone, "domain"));
            let records = self.records_of(&s(zone, "domain"), &s(zone, "subdomain"));
            self.zone_records(zone_name.trim_start_matches('.'), &records, &held, out);
        }
    }

    /// The records fetched for one zone.
    fn records_of(&self, domain: &str, subdomain: &str) -> Vec<&'a Value> {
        let key = if subdomain.is_empty() {
            domain.to_string()
        } else {
            format!("{subdomain}.{domain}")
        };
        self.fetched
            .iter()
            .filter(|f| {
                f.fetch.product == "domain"
                    && f.fetch.resource == "records"
                    && f.fetch.path.contains(&key)
            })
            .flat_map(|f| f.items.iter())
            .collect()
    }

    fn zone_records(
        &self,
        zone: &str,
        records: &[&Value],
        held: &BTreeSet<String>,
        out: &mut Vec<Finding>,
    ) {
        let mut has_caa = false;
        let mut has_dmarc = false;

        for r in records {
            let kind = s(r, "type");
            let data = s(r, "data").trim_end_matches('.').to_ascii_lowercase();
            let name = s(r, "name");
            let full = if name.is_empty() {
                zone.to_string()
            } else {
                format!("{name}.{zone}")
            };

            match kind.as_str() {
                "CAA" => has_caa = true,
                "TXT" if name.starts_with("_dmarc") => {
                    has_dmarc = true;
                    if data.contains("p=none") {
                        out.push(Finding::new(
                            "domain.records.dmarc-none",
                            Severity::High,
                            &full,
                            "DMARC policy is `none`: the domain can be spoofed and nothing will \
                             be rejected",
                        ));
                    }
                }
                "TXT" if data.starts_with("v=spf1") => {
                    if data.ends_with("?all") || data.ends_with("+all") {
                        out.push(Finding::new(
                            "domain.records.spf-weak",
                            Severity::High,
                            &full,
                            "the SPF record ends in ?all or +all, which permits every sender",
                        ));
                    }
                }
                _ => {}
            }

            // A name pointing at Scaleway infrastructure the account does not
            // hold is a name somebody else can take, and the first step of a
            // convincing phish.
            if matches!(kind.as_str(), "CNAME" | "A" | "AAAA")
                && looks_like_scaleway(&data)
                && !held.contains(&data)
            {
                out.push(Finding::new(
                    "domain.records.dangling-cname",
                    Severity::Critical,
                    &full,
                    format!(
                        "{kind} to {data}, which is Scaleway infrastructure this account does \
                         not hold: whoever claims it next answers for this name"
                    ),
                ));
            }

            if name == "*" || name.starts_with("*.") {
                out.push(Finding::new(
                    "domain.records.wildcard",
                    Severity::Medium,
                    &full,
                    "a wildcard record answers for names nobody created, including the ones an \
                     attacker picks",
                ));
            }
            if n(r, "ttl").is_some_and(|t| t > LONG_TTL) {
                out.push(Finding::new(
                    "domain.records.long-ttl",
                    Severity::Low,
                    &full,
                    format!(
                        "TTL of {}, which is how long an incident response would take to take \
                         effect",
                        crate::scw::relative(-n(r, "ttl").unwrap_or(0)).trim_start_matches("in ")
                    ),
                ));
            }
        }

        if !records.is_empty() && !has_caa {
            out.push(Finding::new(
                "domain.records.no-caa",
                Severity::High,
                zone,
                "no CAA record, so any certificate authority in the world may issue for this name",
            ));
        }
        if !records.is_empty() && !has_dmarc {
            out.push(Finding::new(
                "domain.records.dmarc-none",
                Severity::High,
                zone,
                "no DMARC record at all: the domain can be spoofed and you will not hear about it",
            ));
        }
    }

    // ---- device fleets ------------------------------------------------------

    fn iot(&self, now: i64, out: &mut Vec<Finding>) {
        for (region, hub) in self.of("iot", "hubs") {
            let who = format!("{} ({region})", name_or_id(hub));
            if b(hub, "enable_device_auto_provisioning") {
                out.push(Finding::new(
                    "iot.hubs.auto-provisioning",
                    Severity::Critical,
                    &who,
                    "auto-provisioning is on: anything that connects becomes a device",
                ));
            }
            if !b(hub, "has_custom_ca") {
                out.push(Finding::new(
                    "iot.hubs.no-custom-ca",
                    Severity::High,
                    &who,
                    "no custom certificate authority, so device identity rests on what the \
                     platform will issue to anybody",
                ));
            }
            if b(hub, "disable_events") {
                out.push(Finding::new(
                    "iot.hubs.events-disabled",
                    Severity::Medium,
                    &who,
                    "events are disabled, which removes the only record of what the fleet did",
                ));
            }
        }

        for (region, dev) in self.of("iot", "devices") {
            let who = format!("{} ({region})", name_or_id(dev));
            if b(dev, "allow_insecure") {
                out.push(Finding::new(
                    "iot.devices.allow-insecure",
                    Severity::Critical,
                    &who,
                    "may connect without TLS — and so may anything claiming to be it",
                ));
            }
            if b(dev, "allow_multiple_connections") {
                out.push(Finding::new(
                    "iot.devices.shared-identity",
                    Severity::High,
                    &who,
                    "allows several simultaneous connections on one identity, which is how a \
                     single leaked certificate becomes a fleet",
                ));
            }
            if age_secs(dev, "last_activity_at", now).is_some_and(|a| a > DORMANT_DEVICE) {
                out.push(Finding::new(
                    "iot.devices.dormant",
                    Severity::Medium,
                    &who,
                    "no activity for months, still authorized",
                ));
            }
        }

        for (region, route) in self.of("iot", "routes") {
            let Some(rest) = route.get("rest_config") else {
                continue;
            };
            let uri = s(rest, "uri");
            if uri.is_empty() || uri.contains("scw.cloud") {
                continue;
            }
            out.push(Finding::new(
                "iot.routes.foreign-endpoint",
                Severity::High,
                format!("{} ({region})", name_or_id(route)),
                format!("forwards device messages to {uri}, off-platform"),
            ));
        }
    }

    // ---- runners nobody remembers renting -----------------------------------

    fn macs(&self, now: i64, out: &mut Vec<Finding>) {
        for (zone, srv) in self.of("apple-silicon", "servers") {
            let who = format!("{} ({zone})", name_or_id(srv));
            if !s(srv, "sudo_password").is_empty() {
                out.push(Finding::new(
                    "apple-silicon.servers.sudo-password",
                    Severity::Critical,
                    &who,
                    "this listing returned the machine's sudo password: AppleSiliconReadOnly is \
                     administrative access to it, whatever the permission set is called",
                ));
            }
            if age_secs(srv, "updated_at", now).is_some_and(|a| a > IDLE_RUNNER)
                && s(srv, "status") == "ready"
            {
                out.push(Finding::new(
                    "apple-silicon.servers.idle",
                    Severity::Medium,
                    &who,
                    "delivered, untouched for a month, and billed by the day",
                ));
            }
        }
    }

    // ---- the products whose whole job is holding credentials ----------------

    fn vaults(&self, now: i64, out: &mut Vec<Finding>) {
        for (region, sec) in self.of("secret-manager", "secrets") {
            let who = format!("{} ({region})", name_or_id(sec));
            if n(sec, "version_count") == Some(1)
                && age_secs(sec, "created_at", now).is_some_and(|a| a > NEVER_ROTATED)
            {
                out.push(Finding::new(
                    "secret-manager.secrets.never-rotated",
                    Severity::High,
                    &who,
                    "one version, created over a year ago: a credential that has outlived \
                     everyone who knew it",
                ));
            }
            if !b(sec, "protected") {
                out.push(Finding::new(
                    "secret-manager.secrets.unprotected",
                    Severity::Medium,
                    &who,
                    "not protected, so anything with write access can delete it and whatever \
                     depends on it",
                ));
            }
            if len(sec, "used_by") == 0 {
                out.push(Finding::new(
                    "secret-manager.secrets.unused",
                    Severity::Medium,
                    &who,
                    "nothing on the platform references it: either it is dead, or it is read by \
                     something outside IAM's view",
                ));
            }
            if s(sec, "key_id").is_empty() {
                out.push(Finding::new(
                    "secret-manager.secrets.no-key",
                    Severity::Low,
                    &who,
                    "encrypted under the platform key rather than one you control",
                ));
            }
        }

        for (region, key) in self.of("key-manager", "keys") {
            let who = format!("{} ({region})", name_or_id(key));
            if key.get("rotation_policy").is_none_or(Value::is_null) {
                out.push(Finding::new(
                    "key-manager.keys.no-rotation",
                    Severity::High,
                    &who,
                    "no rotation policy: it will be the same key in five years",
                ));
            }
            if !b(key, "protected") {
                out.push(Finding::new(
                    "key-manager.keys.unprotected",
                    Severity::Medium,
                    &who,
                    "not protected: deletable by anything with write access, taking every \
                     ciphertext under it",
                ));
            }
            if n(key, "rotation_count") == Some(0)
                && age_secs(key, "created_at", now).is_some_and(|a| a > NEVER_ROTATED)
            {
                out.push(Finding::new(
                    "key-manager.keys.unused",
                    Severity::Medium,
                    &who,
                    "never rotated since creation over a year ago",
                ));
            }
        }
    }

    // ---- queue credentials --------------------------------------------------

    fn queues(&self, out: &mut Vec<Finding>) {
        for (product, resource, id) in [
            ("mnq", "sqs-credentials", "mnq.sqs-credentials.can-manage"),
            ("mnq", "sns-credentials", "mnq.sns-credentials.can-manage"),
        ] {
            for (region, cred) in self.of(product, resource) {
                let can_manage = cred.get("permissions").is_some_and(|p| b(p, "can_manage"));
                if !can_manage {
                    continue;
                }
                out.push(Finding::new(
                    id,
                    Severity::High,
                    format!("{} ({region})", name_or_id(cred)),
                    "can_manage: this credential can create and delete queues, not only use them",
                ));
            }
        }
    }

    // ---- sending domains ----------------------------------------------------

    fn mail(&self, out: &mut Vec<Finding>) {
        for (region, d) in self.of("tem", "domains") {
            let who = format!("{} ({region})", s(d, "name"));
            let status = s(d, "status");
            if matches!(status.as_str(), "pending" | "unchecked" | "invalid") {
                out.push(Finding::new(
                    "tem.domains.unverified-active",
                    Severity::High,
                    &who,
                    format!(
                        "status is {status}: it is configured to send and its records do not \
                         check out, so what it sends will be treated as forged"
                    ),
                ));
            }
            if s(d, "reputation").to_ascii_lowercase().contains("bad")
                || d.get("reputation")
                    .is_some_and(|r| s(r, "status").eq_ignore_ascii_case("bad"))
            {
                out.push(Finding::new(
                    "tem.domains.reputation",
                    Severity::High,
                    &who,
                    "sending reputation is bad, which is what a compromised sending key looks \
                     like from the outside",
                ));
            }
        }
    }

    // ---- what was left behind -----------------------------------------------

    fn leftovers(&self, now: i64, out: &mut Vec<Finding>) {
        for (zone, img) in self.of("instance", "images") {
            if !self.ours(img) {
                continue;
            }
            let who = format!("{} ({zone})", name_or_id(img));
            if b(img, "public") {
                out.push(Finding::new(
                    "instance.images.public",
                    Severity::Critical,
                    &who,
                    "a custom image marked public: your golden image, and whatever was on its \
                     disk when it was taken, published to every Scaleway customer",
                ));
            } else if age_secs(img, "creation_date", now).is_some_and(|a| a > STALE_IMAGE) {
                out.push(Finding::new(
                    "instance.images.stale",
                    Severity::Medium,
                    &who,
                    "over a year old, and still what new machines are built from",
                ));
            }
        }

        for (product, resource) in [("instance", "volumes"), ("block", "volumes")] {
            for (zone, vol) in self.of(product, resource) {
                let attached =
                    vol.get("server").is_some_and(|v| !v.is_null()) || len(vol, "references") > 0;
                if attached {
                    continue;
                }
                out.push(Finding::new(
                    "instance.volumes.orphan",
                    Severity::Medium,
                    format!("{} ({zone})", name_or_id(vol)),
                    "detached and still billed: the disk of a machine somebody deleted without \
                     it, and whatever was on it",
                ));
            }
        }

        for (product, resource, id) in [
            ("instance", "snapshots", "instance.snapshots.ancient"),
            ("block", "snapshots", "block.snapshots.ancient"),
        ] {
            for (zone, snap) in self.of(product, resource) {
                let created = age_secs(snap, "creation_date", now)
                    .or_else(|| age_secs(snap, "created_at", now));
                if created.is_none_or(|a| a <= ANCIENT_SNAPSHOT) {
                    continue;
                }
                out.push(Finding::new(
                    id,
                    Severity::High,
                    format!("{} ({zone})", name_or_id(snap)),
                    format!(
                        "taken {}: a copy of production data retained past any policy anybody \
                         agreed to, with no firewall in front of it and no expiry on it",
                        crate::scw::relative(created.unwrap_or(0))
                    ),
                ));
            }
        }

        for (region, fs) in self.of("file", "filesystems") {
            if n(fs, "number_of_attachments") != Some(0) {
                continue;
            }
            out.push(Finding::new(
                "file.filesystems.unattached",
                Severity::Low,
                format!("{} ({region})", name_or_id(fs)),
                "mounted by nothing, and still billed",
            ));
        }
    }
}

/// Whether a DNS target names Scaleway infrastructure.
///
/// Only hostnames: an arbitrary IPv4 cannot be attributed to a provider without
/// a prefix list, and guessing would turn every record pointing at another host
/// into a false takeover finding.
fn looks_like_scaleway(target: &str) -> bool {
    let t = target.trim_end_matches('.');
    t.ends_with(".scw.cloud") || t.ends_with(".scaleway.com") || t.ends_with(".s3.fr-par.scw.cloud")
}

#[cfg(test)]
mod tests;
