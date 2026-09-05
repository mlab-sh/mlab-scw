//! The audit catalogue: every Scaleway surface worth reading, and what reading
//! it is for.
//!
//! This is the spine of the tool. Each [`Product`] names one API, where it
//! lives and which permission set opens it; each [`Resource`] names one GET
//! that returns something an auditor cares about; each [`Check`] names one
//! finding that can be derived from that response and nothing else.
//!
//! Keeping it as data rather than as code has three consequences that matter:
//! `mlab-scw catalog` can print the whole audit plan before a single request is
//! made, the least-privilege policy the tool needs can be *generated* from it
//! rather than guessed, and adding a product is a table entry rather than a
//! module.
//!
//! Every path here is a GET. Nothing in this file can change an account.

use crate::scw::client::Paging;
use crate::scw::locality::Scope;

/// How much a finding is worth waking up for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Data or credentials are reachable from the internet right now.
    Critical,
    /// A control that should exist does not, and the exposure is direct.
    High,
    /// A weakness that needs a second condition to be exploited.
    Medium,
    /// Hygiene: it will become one of the above if left alone.
    Low,
    /// Inventory, printed because an auditor asked, not because it is wrong.
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// One derivable finding.
pub struct Check {
    pub severity: Severity,
    /// Stable identifier, `product.resource.slug`, so a finding can be muted.
    pub id: &'static str,
    /// What is looked for, in the words of the person who would have to fix it.
    pub what: &'static str,
}

/// One readable resource.
pub struct Resource {
    pub key: &'static str,
    /// Appended after the product base and its locality segment. `{id}` marks a
    /// segment that comes from `parent`.
    pub path: &'static str,
    /// The body field holding the items, when it is not the only array there.
    pub collection: Option<&'static str>,
    /// The resource whose ids this one is enumerated over.
    pub parent: Option<&'static str>,
    /// A query parameter only the caller can fill, by name — `organization_id`,
    /// `project_id`, `policy_id`, `audience_id` — or empty for none.
    ///
    /// Deliberately a name rather than an enum. The first three were an enum;
    /// then `iam/rules` turned out to want `policy_id` and `iam/jwts`
    /// `audience_id`, both discovered by the API refusing a real call. A name
    /// costs nothing to extend and cannot be wrong in a new way.
    pub needs: &'static str,
    /// Overrides the product's paging. `Paging::None` marks a singleton: one
    /// GET, one object, no page parameters to add.
    pub paging: Option<Paging>,
    /// Why an auditor reads it.
    pub about: &'static str,
    pub checks: &'static [Check],
}

/// One product API.
pub struct Product {
    pub key: &'static str,
    pub name: &'static str,
    /// Product prefix and version, e.g. `/instance/v1`.
    pub base: &'static str,
    pub scope: Scope,
    pub paging: Paging,
    /// The read-only IAM permission set that opens this API.
    pub permission: &'static str,
    pub about: &'static str,
    pub resources: &'static [Resource],
}

impl Product {
    /// The full path of one of its resources, in one locality.
    pub fn path_of(&self, resource: &Resource, locality: &str) -> String {
        format!(
            "{}{}{}",
            self.base,
            self.scope.segment(locality),
            resource.path
        )
    }
}

/// Find a product by key.
pub fn product(key: &str) -> Option<&'static Product> {
    PRODUCTS.iter().find(|p| p.key == key)
}

/// Every read-only permission set the full catalogue needs, deduplicated. This
/// is the policy to attach to the audit application, and nothing more.
pub fn permission_sets() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = PRODUCTS.iter().map(|p| p.permission).collect();
    v.sort_unstable();
    v.dedup();
    v
}

macro_rules! check {
    ($sev:ident, $id:literal, $what:literal) => {
        Check {
            severity: Severity::$sev,
            id: $id,
            what: $what,
        }
    };
}

/// One resource of a paged collection.
///
/// Two macros rather than one optional marker: an optional bare identifier
/// makes the whole invocation ambiguous to `macro_rules!`, because it cannot
/// tell a skipped group from a present one on a single token of lookahead.
macro_rules! res {
    ($key:literal, $path:literal
     $(, needs = $needs:literal)?
     $(, parent = $parent:literal)?
     , $about:literal, [$($c:expr),* $(,)?]) => {
        Resource {
            key: $key,
            path: $path,
            collection: None,
            parent: opt!($($parent)?),
            needs: needs!($($needs)?),
            paging: None,
            about: $about,
            checks: &[$($c),*],
        }
    };
}

/// One singleton GET: one object, no page parameters to add.
macro_rules! one {
    ($key:literal, $path:literal
     $(, needs = $needs:literal)?
     $(, parent = $parent:literal)?
     , $about:literal, [$($c:expr),* $(,)?]) => {
        Resource {
            key: $key,
            path: $path,
            collection: None,
            parent: opt!($($parent)?),
            needs: needs!($($needs)?),
            paging: Some(Paging::None),
            about: $about,
            checks: &[$($c),*],
        }
    };
}

macro_rules! opt {
    () => {
        None
    };
    ($v:literal) => {
        Some($v)
    };
}

macro_rules! needs {
    () => {
        ""
    };
    ($v:literal) => {
        $v
    };
}

/// The catalogue.
pub static PRODUCTS: &[Product] = &[
    // ---- who can do what ---------------------------------------------------
    Product {
        key: "iam",
        name: "IAM",
        base: "/iam/v1alpha1",
        scope: Scope::Global,
        paging: Paging::Page,
        permission: "IAMReadOnly",
        about: "Principals, credentials and the policies that bind them. The first \
                thing to read and the last thing to fix: every other finding in this \
                catalogue is reachable by whoever holds the wrong key here.",
        resources: &[
            res!("users", "/users", needs = "organization_id",
                "Human accounts, their MFA state and their last login.", [
                check!(Critical, "iam.users.no-mfa", "a member without two-factor authentication, in an organization that does not enforce it"),
                check!(High, "iam.users.owner-daily-driver", "the owner account used for day-to-day work instead of a scoped application"),
                check!(Medium, "iam.users.dormant", "no login for 90 days: an account nobody would notice being used"),
                check!(Medium, "iam.users.locked", "a locked account still carrying policies"),
            ]),
            res!("applications", "/applications", needs = "organization_id",
                "Non-human principals. Each one is an API key with a purpose written on it — or without.", [
                check!(Medium, "iam.applications.keyless", "an application with no API key: a policy attached to nothing, and a name that no longer means anything"),
                check!(Low, "iam.applications.undescribed", "no description, so nobody can say what breaks if it is deleted"),
            ]),
            res!("api-keys", "/api-keys", needs = "organization_id",
                "Every credential that can call this API, and what it is bearing.", [
                check!(Critical, "iam.api-keys.never-expires", "no expiry date: the credential outlives the person, the project and the reason it was made"),
                check!(High, "iam.api-keys.stale", "created over a year ago and never rotated"),
                check!(High, "iam.api-keys.user-bound", "a key bound to a human rather than an application, so it inherits every permission that person will ever be given"),
                check!(Low, "iam.api-keys.default-project", "an Object Storage preferred project of `default`: the choice is fixed at key creation and cannot be overridden per call, so this key can never see another project's buckets however wide its policy is"),
                check!(Info, "iam.api-keys.creation-ip", "the address the key was created from, which is the only provenance the API keeps"),
            ]),
            res!("policies", "/policies", needs = "organization_id",
                "The bindings. A policy is a principal plus rules, and rules are where over-permission hides.", [
                check!(Critical, "iam.policies.no-principal", "a policy with no principal: dormant permission that becomes live the moment someone is attached"),
                check!(Critical, "iam.policies.all-products-full-access", "AllProductsFullAccess granted at organization scope — the account's root, handed out by name"),
                check!(High, "iam.policies.org-scope", "organization-wide scope where a project list would have done"),
                check!(Medium, "iam.policies.unused", "a policy whose principal has never authenticated"),
            ]),
            res!("rules", "/rules", needs = "policy_id", parent = "policies",
                "The permission sets and scopes inside one policy: the actual grant. \
                 Enumerated per policy: `policy_id` is required, and the API refuses \
                 the call without it.", [
                check!(High, "iam.rules.write-in-a-read-role", "a FullAccess permission set inside a policy named for reading"),
                check!(Medium, "iam.rules.condition-free", "no CEL condition on a rule that grants outside a single project"),
            ]),
            res!("groups", "/groups", needs = "organization_id",
                "Group membership, which is how a permission arrives without anyone granting it.", [
                check!(High, "iam.groups.everyone", "a group defined as all_users or all_applications, carrying policies: a standing grant to every principal the organization will ever have, including the ones nobody has created yet"),
                check!(Medium, "iam.groups.empty", "an empty group holding policies"),
                check!(Low, "iam.groups.mixed", "users and applications in one group, so a human grant silently becomes a machine grant"),
            ]),
            res!("ssh-keys", "/ssh-keys", needs = "organization_id",
                "Keys injected into every Instance and Elastic Metal server at boot.", [
                check!(High, "iam.ssh-keys.stale", "added over two years ago and still injected into every machine created since — the API records no owner for a key, so age is the only handle on \"whose is this\""),
                check!(Medium, "iam.ssh-keys.weak", "an RSA key under 3072 bits, or a DSA key, read out of the key's own wire format"),
                check!(Low, "iam.ssh-keys.disabled", "disabled but not deleted"),
            ]),
            one!("security-settings", "/organizations/{id}/security-settings", parent = "organizations",
                "The organization's own password, session and key-expiry rules.", [
                check!(High, "iam.security-settings.no-key-expiry", "max_api_key_expiration_duration unset: keys may be created that never expire"),
                check!(Medium, "iam.security-settings.long-sessions", "a login session longer than a working day"),
                check!(Medium, "iam.security-settings.no-lockout", "login_attempts_before_locked unset or high"),
            ]),
            res!("logs", "/logs", needs = "organization_id",
                "IAM's own change log: who granted what, from where.", [
                check!(High, "iam.logs.grant-outside-hours", "a permission granted outside working hours or from an unfamiliar address"),
                check!(Info, "iam.logs.coverage", "how far back the log actually goes, which bounds every other answer"),
            ]),
            res!("jwts", "/jwts", needs = "audience_id", parent = "users",
                "Live console sessions, with the address and agent that opened them. \
                 Enumerated per user: `audience_id` is the user, and is required.", [
                check!(High, "iam.jwts.foreign-ip", "a session from an address no other session has used"),
            ]),
        ],
    },
    // ---- the account itself ------------------------------------------------
    Product {
        key: "account",
        name: "Account",
        base: "/account/v3",
        scope: Scope::Global,
        paging: Paging::Page,
        permission: "ProjectReadOnly",
        about: "Projects. Every regional and zonal listing is filtered by project, so \
                this is the list that decides whether a sweep is complete.",
        resources: &[
            res!("projects", "/projects", needs = "organization_id",
                "The projects a key can see. An audit that misses one reports a clean account.", [
                check!(High, "account.projects.invisible", "the key is scoped to fewer projects than the organization has, so the sweep is partial and must say so"),
                check!(Low, "account.projects.default-only", "everything in the default project: no blast-radius boundary anywhere"),
            ]),
        ],
    },
    // ---- compute -----------------------------------------------------------
    Product {
        key: "instance",
        name: "Instances",
        base: "/instance/v1",
        scope: Scope::Zone,
        paging: Paging::PerPage,
        permission: "InstancesReadOnly",
        about: "Virtual machines, their addresses, their firewalls and the disks and \
                images left behind them.",
        resources: &[
            res!("servers", "/servers",
                "Every VM, with its public addresses, its security group and its boot volumes.", [
                check!(Critical, "instance.servers.public-no-filter", "a public IPv4 on a server whose security group defaults to accept inbound"),
                check!(High, "instance.servers.default-group", "left in the project's default security group, which is shared with everything else"),
                check!(Medium, "instance.servers.unprotected", "protected=false on a production-tagged machine: one API call from deletion"),
                check!(Medium, "instance.servers.end-of-service", "an offer past end of service, so it will stop being patched"),
                check!(Low, "instance.servers.legacy-networking", "routed_ip_enabled=false: the old NAT model, which the security group treats differently"),
            ]),
            one!("user-data", "/servers/{id}/user_data", parent = "servers",
                "cloud-init. The single most reliable place to find a plaintext credential in any cloud account.", [
                check!(Critical, "instance.user-data.secret", "an API key, password, private key or database URL in cloud-init, readable by anything with InstancesReadOnly and by the machine itself over the metadata address"),
                check!(Medium, "instance.user-data.fetches-unpinned", "cloud-init pulling a script over the network with no checksum"),
            ]),
            res!("security-groups", "/security_groups",
                "The firewall. Default policies matter more than rules: a permissive default outlives every rule written under it.", [
                check!(Critical, "instance.security-groups.inbound-accept", "inbound_default_policy=accept, which makes every rule below it decoration"),
                check!(High, "instance.security-groups.stateless", "stateful=false without a matching outbound rule set"),
                check!(Medium, "instance.security-groups.unused", "attached to no server, so nobody will notice it drifting"),
            ]),
            res!("security-group-rules", "/security_groups/{id}/rules", parent = "security-groups",
                "The rules themselves, in order.", [
                check!(Critical, "instance.security-group-rules.world-ssh", "0.0.0.0/0 to 22, 3389, 5900 or 5432: administration and databases open to the internet"),
                check!(High, "instance.security-group-rules.world-any", "0.0.0.0/0 to any port"),
                check!(Medium, "instance.security-group-rules.wide-range", "a port range wider than a hundred ports from a public prefix"),
                check!(Low, "instance.security-group-rules.shadowed", "a rule below a broader one at a lower position, which will never match"),
            ]),
            res!("ips", "/ips",
                "Flexible IPv4 and IPv6, attached or not.", [
                check!(High, "instance.ips.dangling", "an address reserved but attached to nothing, while a DNS record still points at it — the classic subdomain takeover, on your own bill"),
                check!(Low, "instance.ips.reverse-mismatch", "a reverse DNS name that no longer resolves back"),
            ]),
            res!("volumes", "/volumes",
                "Block devices, attached or orphaned.", [
                check!(Medium, "instance.volumes.orphan", "detached and paid for: the data of a machine that was deleted without its disk"),
                check!(Info, "instance.volumes.export-uri", "the export URI, which says how the volume is reachable"),
            ]),
            res!("snapshots", "/snapshots",
                "Point-in-time copies. A snapshot has no firewall and outlives the policy of the machine it came from.", [
                check!(High, "instance.snapshots.ancient", "older than a year: data retained past the retention anybody agreed to"),
                check!(Low, "instance.snapshots.unnamed", "no name, so nobody will ever dare delete it"),
            ]),
            res!("images", "/images",
                "Custom images built from a running machine — including whatever was on its disk at the time.", [
                check!(Critical, "instance.images.public", "public=true on a custom image: your golden image, and its baked-in credentials, published to every Scaleway customer"),
                check!(Medium, "instance.images.stale", "over a year old and still the base for new machines"),
            ]),
            res!("private-nics", "/servers/{id}/private_nics", parent = "servers",
                "Attachment to Private Networks: the map of what can reach what without touching the internet.", [
                check!(Medium, "instance.private-nics.bridge", "a machine on both a public address and a private network, which makes it the way in"),
            ]),
            res!("placement-groups", "/placement_groups",
                "Physical placement policy.", [
                check!(Low, "instance.placement-groups.no-spread", "a high-availability pair on the same hypervisor"),
            ]),
        ],
    },
    Product {
        key: "baremetal",
        name: "Elastic Metal",
        base: "/baremetal/v1",
        scope: Scope::Zone,
        paging: Paging::Page,
        permission: "ElasticMetalReadOnly",
        about: "Dedicated servers. No hypervisor firewall in front of them, so the \
                whole exposure is whatever the OS does.",
        resources: &[
            res!("servers", "/servers",
                "The machines, their addresses, the OS installed and whether rescue mode is on.", [
                check!(Critical, "baremetal.servers.rescue", "left in rescue mode, which is a root shell reachable with a password the API will hand you"),
                check!(High, "baremetal.servers.no-private-network", "public addresses only: nothing between the machine and the internet but its own firewall"),
                check!(Medium, "baremetal.servers.unprotected", "protected=false"),
                check!(Medium, "baremetal.servers.user-data", "installation user data, read the same way Instance cloud-init is"),
            ]),
            one!("bmc", "/servers/{id}/bmc-access", parent = "servers",
                "Out-of-band console access: a URL, a login and a password.", [
                check!(Critical, "baremetal.bmc.open", "a live BMC session: keyboard and screen on the machine, below the operating system, with credentials this API returns in plaintext"),
            ]),
        ],
    },
    Product {
        key: "apple-silicon",
        name: "Apple silicon",
        base: "/apple-silicon/v1alpha1",
        scope: Scope::Zone,
        paging: Paging::Page,
        permission: "AppleSiliconReadOnly",
        about: "Mac runners. The only product whose read API returns the machine's own \
                administrator password.",
        resources: &[
            res!("servers", "/servers",
                "The runners, their public address, their VNC endpoint and their sudo password.", [
                check!(Critical, "apple-silicon.servers.sudo-password", "sudo_password returned by a read call: AppleSiliconReadOnly is administrative access to the machine, whatever the name says"),
                check!(Critical, "apple-silicon.servers.vnc", "a VNC URL on a public address"),
                check!(Medium, "apple-silicon.servers.idle", "delivered, unused and billed by the day"),
            ]),
        ],
    },
    // ---- containers --------------------------------------------------------
    Product {
        key: "k8s",
        name: "Kubernetes Kapsule",
        base: "/k8s/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "KubernetesReadOnly",
        about: "Managed clusters. The control plane's exposure, the nodes' exposure and \
                the admission configuration are three different problems.",
        resources: &[
            res!("clusters", "/clusters",
                "Version, CNI, admission plugins, feature gates, OIDC and the API server's certificate names.", [
                check!(Critical, "k8s.clusters.public-apiserver-no-acl", "a public control plane with acl_available and no rule narrowing it: kube-apiserver on the open internet"),
                check!(High, "k8s.clusters.eol-version", "a Kubernetes version past upstream support, so CVEs are no longer backported"),
                check!(High, "k8s.clusters.no-auto-upgrade", "auto_upgrade disabled and an upgrade available"),
                check!(High, "k8s.clusters.cni-no-policy", "a CNI without NetworkPolicy support, so every pod can reach every pod"),
                check!(Medium, "k8s.clusters.no-oidc", "no OpenID Connect: cluster access rests entirely on IAM keys, and every audit-log entry says the same name"),
                check!(Medium, "k8s.clusters.risky-feature-gates", "an alpha feature gate or a permissive admission plugin set"),
                check!(Low, "k8s.clusters.wildcard-dns", "a dns_wildcard record pointing at ingress, which enumerates the cluster's services"),
            ]),
            res!("acls", "/clusters/{id}/acls", parent = "clusters",
                "Who may reach the control plane.", [
                check!(Critical, "k8s.acls.world", "0.0.0.0/0 in the control-plane allow list"),
                check!(Low, "k8s.acls.stale-office", "an allow entry for an address range nobody uses any more"),
            ]),
            res!("pools", "/clusters/{id}/pools", parent = "clusters",
                "Node pools: their size, their image, and whether their nodes hold public addresses.", [
                check!(High, "k8s.pools.public-nodes", "public_ip_disabled=false: every node individually reachable, so a node's kubelet and NodePorts are internet-facing"),
                check!(High, "k8s.pools.no-autohealing", "autohealing off, so a compromised or broken node stays in the cluster"),
                check!(Medium, "k8s.pools.version-skew", "a pool trailing the control plane by more than one minor version"),
                check!(Medium, "k8s.pools.kubelet-args", "custom kubelet arguments, which is where anonymous-auth gets turned back on"),
            ]),
            res!("nodes", "/clusters/{id}/nodes", parent = "clusters",
                "The nodes as the control plane sees them.", [
                check!(Medium, "k8s.nodes.not-ready", "a node stuck outside Ready, which usually means an upgrade half-applied"),
            ]),
        ],
    },
    Product {
        key: "registry",
        name: "Container Registry",
        base: "/registry/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "ContainerRegistryReadOnly",
        about: "Image namespaces. One boolean here publishes your build output to the world.",
        resources: &[
            res!("namespaces", "/namespaces",
                "The namespaces and their visibility.", [
                check!(Critical, "registry.namespaces.public", "is_public=true: every image, every layer and every secret baked into them, pullable anonymously"),
                check!(Low, "registry.namespaces.empty", "an empty namespace still holding a name"),
            ]),
            res!("images", "/images",
                "Images and their per-image visibility override.", [
                check!(Critical, "registry.images.public", "visibility=public on an image inside a private namespace"),
                check!(Medium, "registry.images.stale", "no push in a year, still deployed"),
            ]),
            res!("tags", "/images/{id}/tags", parent = "images",
                "Tags, and whether anything mutable is deployed.", [
                check!(Medium, "registry.tags.latest-in-production", "a deployment pinned to a mutable tag, so what runs is not what was reviewed"),
            ]),
        ],
    },
    Product {
        key: "containers",
        name: "Serverless Containers",
        base: "/containers/v1beta1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "ContainersReadOnly",
        about: "Containers as HTTP endpoints. Privacy and environment variables are the \
                whole story.",
        resources: &[
            res!("namespaces", "/namespaces",
                "Namespace-wide environment, inherited by every container in it.", [
                check!(Critical, "containers.namespaces.plaintext-secret", "a credential in environment_variables rather than secret_environment_variables: readable by anyone with the read-only permission set, and inherited by every container"),
            ]),
            res!("containers", "/containers",
                "Each container's privacy, its domain, its scaling and its environment.", [
                check!(Critical, "containers.containers.public", "privacy=public: an unauthenticated HTTPS endpoint, indexed and reachable by anyone"),
                check!(Critical, "containers.containers.plaintext-secret", "a credential in environment_variables"),
                check!(High, "containers.containers.http-redirected-off", "http_option allowing plain HTTP"),
                check!(Medium, "containers.containers.v1-sandbox", "sandbox=v1, the weaker isolation mode"),
                check!(Medium, "containers.containers.min-scale-zero-public", "a public endpoint with no rate ceiling: max_scale is the only thing between a scraper and the bill"),
            ]),
            res!("triggers", "/triggers",
                "What invokes a container besides HTTP.", [
                check!(Medium, "containers.triggers.foreign-queue", "a trigger reading a queue in another project"),
            ]),
            res!("domains", "/domains",
                "Custom domains bound to a container.", [
                check!(High, "containers.domains.dangling", "a custom domain whose DNS no longer resolves here, or resolves here for a name you no longer own"),
            ]),
        ],
    },
    Product {
        key: "functions",
        name: "Serverless Functions",
        base: "/functions/v1beta1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "FunctionsReadOnly",
        about: "The same shape as Containers, plus a runtime that goes end of life.",
        resources: &[
            res!("namespaces", "/namespaces", "Namespace-wide environment.", [
                check!(Critical, "functions.namespaces.plaintext-secret", "a credential in environment_variables"),
            ]),
            res!("functions", "/functions",
                "Privacy, runtime, handler and environment.", [
                check!(Critical, "functions.functions.public", "privacy=public"),
                check!(Critical, "functions.functions.plaintext-secret", "a credential in environment_variables"),
                check!(High, "functions.functions.eol-runtime", "a runtime past end of support, which stops receiving patches while the function keeps serving"),
                check!(High, "functions.functions.http-redirected-off", "http_option allowing plain HTTP"),
            ]),
        ],
    },
    Product {
        key: "jobs",
        name: "Serverless Jobs",
        base: "/serverless-jobs/v1alpha2",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "ServerlessJobsReadOnly",
        about: "Scheduled batch work: the part of an account nobody looks at.",
        resources: &[
            res!("job-definitions", "/job-definitions",
                "Image, command, schedule and environment.", [
                check!(Critical, "jobs.job-definitions.plaintext-secret", "a credential in environment_variables rather than a Secret Manager reference"),
                check!(Medium, "jobs.job-definitions.foreign-image", "an image_uri outside your own registry"),
                check!(Medium, "jobs.job-definitions.no-timeout", "no job_timeout on a cron job, so a hung run bills until someone notices"),
            ]),
            res!("job-runs", "/job-runs",
                "What actually ran, and how it ended.", [
                check!(Medium, "jobs.job-runs.silent-failure", "a cron job failing every run for weeks with nothing watching"),
            ]),
        ],
    },
    // ---- data --------------------------------------------------------------
    Product {
        key: "rdb",
        name: "Managed Database",
        base: "/rdb/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "RelationalDatabasesReadOnly",
        about: "PostgreSQL and MySQL. The exposure is the endpoint list; the control is \
                the ACL list; both are readable.",
        resources: &[
            res!("instances", "/instances",
                "Engine version, high availability, backup schedule, encryption and endpoints.", [
                check!(Critical, "rdb.instances.public-endpoint", "a load-balancer endpoint on the public internet, which is the default and stays the default"),
                check!(High, "rdb.instances.no-encryption", "encryption at rest off"),
                check!(High, "rdb.instances.no-backup", "no backup schedule, or a retention shorter than the time it takes to notice a deletion"),
                check!(High, "rdb.instances.eol-engine", "an engine version past upstream support"),
                check!(Medium, "rdb.instances.no-ha", "is_ha_cluster=false on something described as production"),
                check!(Medium, "rdb.instances.backup-same-region", "backups in the region they protect against losing"),
            ]),
            res!("acls", "/instances/{id}/acls", parent = "instances",
                "Which source prefixes may connect.", [
                check!(Critical, "rdb.acls.world", "0.0.0.0/0: the database is on the internet with a password as its only control"),
                check!(High, "rdb.acls.wide", "a prefix shorter than /24 from a public range"),
                check!(Low, "rdb.acls.stale", "an allow entry describing an office or a supplier that is gone"),
            ]),
            res!("users", "/instances/{id}/users", parent = "instances",
                "Database roles and which are administrative.", [
                check!(High, "rdb.users.many-admins", "more than one administrative role, so no login is individually attributable"),
                check!(Medium, "rdb.users.app-is-admin", "the application's own login is an admin"),
            ]),
            res!("snapshots", "/snapshots",
                "Database snapshots and their age.", [
                check!(High, "rdb.snapshots.ancient", "a snapshot older than the retention policy anyone signed off"),
            ]),
        ],
    },
    Product {
        key: "redis",
        name: "Redis",
        base: "/redis/v1",
        scope: Scope::Zone,
        paging: Paging::Page,
        permission: "RedisReadOnly",
        about: "In-memory data. Historically the fastest way to lose a dataset to a scanner.",
        resources: &[
            res!("clusters", "/clusters",
                "TLS, ACL rules and whether an endpoint faces the public network.", [
                check!(Critical, "redis.clusters.public-no-acl", "a public_network endpoint with an ACL rule of 0.0.0.0/0"),
                check!(Critical, "redis.clusters.no-tls", "tls_enabled=false: the password and every value cross the network in clear"),
                check!(High, "redis.clusters.eol-version", "a version past support"),
            ]),
        ],
    },
    Product {
        key: "mongodb",
        name: "MongoDB",
        base: "/mongodb/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "MongoDBReadOnly",
        about: "Managed MongoDB, with the same public/private endpoint question.",
        resources: &[
            res!("instances", "/instances",
                "Endpoints, version and snapshot schedule.", [
                check!(Critical, "mongodb.instances.public-endpoint", "a public_network endpoint"),
                check!(High, "mongodb.instances.no-snapshot-schedule", "no automatic snapshots"),
            ]),
            res!("users", "/instances/{id}/users", parent = "instances",
                "Roles per database.", [
                check!(High, "mongodb.users.root", "a user with a cluster-wide role where a database-scoped one would do"),
            ]),
        ],
    },
    Product {
        key: "searchdb",
        name: "OpenSearch",
        base: "/searchdb/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "SearchDBReadOnly",
        about: "Managed OpenSearch: a search index is a copy of the data it indexes.",
        resources: &[
            res!("deployments", "/deployments",
                "Endpoints and whether they are public.", [
                check!(Critical, "searchdb.deployments.public", "a public endpoint on an index that mirrors production data"),
            ]),
        ],
    },
    Product {
        key: "kafka",
        name: "Kafka",
        base: "/kafka/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "KafkaClusterReadOnly",
        about: "Event streams, which carry whatever the producers put in them.",
        resources: &[
            res!("clusters", "/clusters",
                "Endpoints, version and settings.", [
                check!(Critical, "kafka.clusters.public", "a public_network endpoint"),
            ]),
        ],
    },
    Product {
        key: "serverless-sqldb",
        name: "Serverless SQL Database",
        base: "/serverless-sqldb/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "ServerlessSQLDatabaseReadOnly",
        about: "PostgreSQL billed by the query, reachable with an IAM token rather than a password.",
        resources: &[
            res!("databases", "/databases", needs = "project_id",
                "Databases and their scaling floor.", [
                check!(High, "serverless-sqldb.databases.broad-access", "access granted by a permission set rather than to a named application, so any key in the project can read it"),
                check!(Low, "serverless-sqldb.databases.min-cpu", "a non-zero floor on something idle"),
            ]),
        ],
    },
    Product {
        key: "block",
        name: "Block Storage",
        base: "/block/v1",
        scope: Scope::Zone,
        paging: Paging::Page,
        permission: "BlockStorageReadOnly",
        about: "Volumes and snapshots, independent of the machines they were attached to.",
        resources: &[
            res!("volumes", "/volumes",
                "Volumes and their attachment references.", [
                check!(Medium, "block.volumes.orphan", "detached, undeleted and billed: the disk of a machine somebody removed"),
            ]),
            res!("snapshots", "/snapshots",
                "Snapshots and their class.", [
                check!(High, "block.snapshots.ancient", "retained past any stated policy"),
            ]),
        ],
    },
    Product {
        key: "file",
        name: "File Storage",
        base: "/file/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "FileStorageReadOnly",
        about: "Shared filesystems, and how many things are mounted on them.",
        resources: &[
            res!("filesystems", "/filesystems",
                "Filesystems and their attachments.", [
                check!(Medium, "file.filesystems.shared-widely", "one filesystem mounted by machines in different trust zones"),
                check!(Low, "file.filesystems.unattached", "attached to nothing and still billed"),
            ]),
        ],
    },
    // ---- network -----------------------------------------------------------
    Product {
        key: "vpc",
        name: "VPC",
        base: "/vpc/v2",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "VPCReadOnly",
        about: "The private side of the account: what is segmented from what.",
        resources: &[
            res!("vpcs", "/vpcs",
                "VPCs, their routing and their default status.", [
                check!(Medium, "vpc.vpcs.default-only", "everything in the default VPC: no segmentation to speak of"),
                check!(Medium, "vpc.vpcs.routing-enabled-flat", "routing on with no ACL rules, so every private network reaches every other"),
            ]),
            res!("acl-rules", "/vpcs/{id}/acl-rules", parent = "vpcs",
                "The rules between private networks: the only east-west control Scaleway offers.", [
                check!(High, "vpc.acl-rules.default-allow", "no rules at all on a routed VPC, which is a flat network by another name"),
                check!(Medium, "vpc.acl-rules.any-any", "an any/any allow rule that makes the rest of the list decoration"),
            ]),
            res!("private-networks", "/private-networks",
                "The networks themselves, their subnets and their DHCP.", [
                check!(Low, "vpc.private-networks.overlap", "subnets that overlap another VPC's, which blocks any future peering"),
            ]),
        ],
    },
    Product {
        key: "vpc-gw",
        name: "Public Gateways",
        base: "/vpc-gw/v2",
        scope: Scope::Zone,
        paging: Paging::Page,
        permission: "VPCGatewayReadOnly",
        about: "The door between a private network and the internet, in both directions.",
        resources: &[
            res!("gateways", "/gateways",
                "The gateways, their public address, and whether the SSH bastion is on.", [
                check!(Critical, "vpc-gw.gateways.bastion-open", "bastion_enabled with bastion_allowed_ips empty or 0.0.0.0/0: an SSH jump host into the private network, open to the internet"),
                check!(Medium, "vpc-gw.gateways.smtp", "smtp_enabled on a gateway that has no business sending mail"),
                check!(Medium, "vpc-gw.gateways.legacy", "is_legacy: a generation that no longer gets features, including the newer bastion controls"),
            ]),
            res!("pat-rules", "/pat-rules",
                "Port forwards from the public address into the private network.", [
                check!(Critical, "vpc-gw.pat-rules.admin-port", "a forward to 22, 3389, 3306 or 5432: a private machine published to the internet on an administrative port"),
                check!(High, "vpc-gw.pat-rules.forgotten", "a forward to a private address nothing answers on any more, which will publish whatever takes that address next"),
            ]),
            res!("gateway-networks", "/gateway-networks",
                "Which private networks a gateway is attached to, and whether it masquerades.", [
                check!(Medium, "vpc-gw.gateway-networks.default-route", "push_default_route sending a whole private network out through one gateway"),
            ]),
        ],
    },
    Product {
        key: "lb",
        name: "Load Balancer",
        base: "/lb/v1",
        scope: Scope::Zone,
        paging: Paging::Page,
        permission: "LoadBalancersReadOnly",
        about: "The front door of most accounts: TLS termination, ACLs and what sits behind.",
        resources: &[
            res!("lbs", "/lbs",
                "The load balancers and their TLS compatibility level.", [
                check!(High, "lb.lbs.old-ssl-level", "ssl_compatibility_level allowing TLS 1.0 or 1.1"),
                check!(Medium, "lb.lbs.no-private-network", "no private network attachment, so traffic to the backends crosses the public network"),
            ]),
            res!("frontends", "/lbs/{id}/frontends", parent = "lbs",
                "Listening ports, their certificates and their access logs.", [
                check!(High, "lb.frontends.plain-http", "a listener on 80 with no redirect rule above it"),
                check!(High, "lb.frontends.no-certificate", "a listener on 443 with no certificate attached"),
                check!(Medium, "lb.frontends.no-access-logs", "enable_access_logs=false: nothing to look at after an incident"),
                check!(Medium, "lb.frontends.no-rate-limit", "no connection_rate_limit on a public listener"),
            ]),
            res!("acls", "/frontends/{id}/acls", parent = "frontends",
                "Who may reach a frontend, and on which paths.", [
                check!(High, "lb.acls.admin-path-open", "an /admin, /actuator or /.git path with no allow-list in front of it"),
                check!(Medium, "lb.acls.none", "no ACLs at all on an internet-facing frontend"),
            ]),
            res!("backends", "/lbs/{id}/backends", parent = "lbs",
                "How the load balancer talks to what is behind it.", [
                check!(High, "lb.backends.ignore-ssl-verify", "ignore_ssl_server_verify=true: TLS to the backend with the certificate check turned off, which is encryption without authentication"),
                check!(Medium, "lb.backends.no-health-check", "a health check that only opens a socket, so a broken application stays in rotation"),
                check!(Medium, "lb.backends.plain-backend", "ssl_bridging off with backends on a public network"),
            ]),
            res!("certificates", "/lbs/{id}/certificates", parent = "lbs",
                "Certificates, their names and their expiry.", [
                check!(Critical, "lb.certificates.expired", "not_valid_after in the past"),
                check!(High, "lb.certificates.expiring", "expiring within 30 days"),
                check!(Medium, "lb.certificates.name-mismatch", "a common name and SAN set that does not cover the DNS pointing at this load balancer"),
            ]),
            res!("ips", "/ips",
                "The addresses, attached or reserved.", [
                check!(Medium, "lb.ips.dangling", "reserved, unattached, and still named in DNS"),
            ]),
        ],
    },
    Product {
        key: "ipam",
        name: "IPAM",
        base: "/ipam/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "IPAMReadOnly",
        about: "The one place that maps every address in the account to the resource \
                holding it — which is how a public-exposure inventory is completed \
                rather than assembled product by product.",
        resources: &[
            res!("ips", "/ips",
                "Every managed address, with its resource and its zone.", [
                check!(High, "ipam.ips.public-inventory", "the full list of publicly-routable addresses in the account, which is the attack surface, stated once"),
                check!(Medium, "ipam.ips.unattached", "an address held by nothing"),
            ]),
        ],
    },
    Product {
        key: "flexible-ip",
        name: "Flexible IP",
        base: "/flexible-ip/v1alpha1",
        scope: Scope::Zone,
        paging: Paging::Page,
        permission: "ElasticMetalReadOnly",
        about: "Addresses that move between Elastic Metal servers, with their reverse DNS.",
        resources: &[
            res!("fips", "/fips",
                "The addresses and where they point.", [
                check!(High, "flexible-ip.fips.dangling", "detached but still the target of a DNS record"),
            ]),
        ],
    },
    Product {
        key: "edge-services",
        name: "Edge Services",
        base: "/edge-services/v1beta1",
        scope: Scope::Global,
        paging: Paging::Page,
        permission: "EdgeServicesReadOnly",
        about: "CDN, TLS and WAF in front of a bucket, a load balancer or a container.",
        resources: &[
            res!("pipelines", "/pipelines",
                "The pipelines and their errors.", [
                check!(Medium, "edge-services.pipelines.errored", "a pipeline in error, which usually means traffic is bypassing it"),
            ]),
            res!("waf-stages", "/pipelines/{id}/waf-stages", parent = "pipelines",
                "Whether the WAF blocks or only watches.", [
                check!(High, "edge-services.waf-stages.detection-only", "mode set to detection: the rules run, nothing is stopped, and the dashboard looks protected"),
                check!(Medium, "edge-services.waf-stages.low-paranoia", "the lowest paranoia level on an application handling personal data"),
            ]),
            res!("tls-stages", "/pipelines/{id}/tls-stages", parent = "pipelines",
                "Certificates at the edge and when they expire.", [
                check!(High, "edge-services.tls-stages.expiring", "certificate_expires_at inside 30 days"),
            ]),
            res!("backend-stages", "/pipelines/{id}/backend-stages", parent = "pipelines",
                "What the edge fronts, which says what is meant to be private behind it.", [
                check!(High, "edge-services.backend-stages.origin-reachable", "an S3 or load-balancer origin still reachable directly, so the WAF and the cache can both be walked around"),
            ]),
        ],
    },
    Product {
        key: "s2s-vpn",
        name: "Site-to-Site VPN",
        base: "/s2s-vpn/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "SiteToSiteVPNReadOnly",
        about: "Tunnels to somewhere else, and the ciphers they were agreed on.",
        resources: &[
            res!("connections", "/connections",
                "IKEv2 and ESP cipher suites, tunnel state and route propagation.", [
                check!(High, "s2s-vpn.connections.weak-ciphers", "a cipher suite below current guidance"),
                check!(Medium, "s2s-vpn.connections.route-propagation", "route propagation pushing a partner's routes into your VPC unfiltered"),
                check!(Medium, "s2s-vpn.connections.down", "a tunnel down long enough that whatever depended on it found another way"),
            ]),
            res!("customer-gateways", "/customer-gateways",
                "The far end of each tunnel.", [
                check!(Low, "s2s-vpn.customer-gateways.orphan", "a gateway for a partner that is gone"),
            ]),
        ],
    },
    // ---- secrets and keys --------------------------------------------------
    Product {
        key: "secret-manager",
        name: "Secret Manager",
        base: "/secret-manager/v1beta1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "SecretManagerReadOnly",
        about: "Where credentials are supposed to be. Metadata only: SecretManagerReadOnly \
                deliberately does not open version data, and this tool never asks for it.",
        resources: &[
            res!("secrets", "/secrets",
                "Names, paths, versions, protection and rotation.", [
                check!(High, "secret-manager.secrets.never-rotated", "one version, created years ago: a credential that has outlived everyone who knew it"),
                check!(Medium, "secret-manager.secrets.unprotected", "protected=false on something production depends on"),
                check!(Medium, "secret-manager.secrets.unused", "used_by empty: either dead, or used by something that reads it outside IAM"),
                check!(Low, "secret-manager.secrets.no-key", "no key_id, so the secret is under the platform key rather than one you control"),
            ]),
            res!("versions", "/secrets/{id}/versions", parent = "secrets",
                "Version history and status. Metadata; the value is never fetched.", [
                check!(Medium, "secret-manager.versions.enabled-old", "old versions left enabled, so a leaked one still works"),
            ]),
        ],
    },
    Product {
        key: "key-manager",
        name: "Key Manager",
        base: "/key-manager/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "KeyManagerReadOnly",
        about: "The keys other products encrypt with.",
        resources: &[
            res!("keys", "/keys",
                "Usage, origin, rotation policy and protection.", [
                check!(High, "key-manager.keys.no-rotation", "no rotation policy on a key in use"),
                check!(Medium, "key-manager.keys.unprotected", "protected=false: deletable by anyone who can write, taking every ciphertext with it"),
                check!(Medium, "key-manager.keys.unused", "a key nothing references"),
            ]),
        ],
    },
    // ---- messaging, mail, DNS ---------------------------------------------
    Product {
        key: "mnq",
        name: "Messaging & Queuing",
        base: "/mnq/v1beta1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "MessagingAndQueuingReadOnly",
        about: "NATS, SQS and SNS. The credentials here are separate from IAM and expire \
                only when somebody deletes them.",
        resources: &[
            res!("sqs-credentials", "/sqs-credentials", needs = "project_id",
                "Per-credential permissions: can receive, can publish, can manage.", [
                check!(High, "mnq.sqs-credentials.can-manage", "can_manage on a credential that only needs to consume"),
                check!(Medium, "mnq.sqs-credentials.stale", "created long ago, never rotated, no expiry to rotate it for you"),
            ]),
            res!("sns-credentials", "/sns-credentials", needs = "project_id",
                "The same for notifications.", [
                check!(High, "mnq.sns-credentials.can-manage", "can_manage on a publisher"),
            ]),
            res!("nats-accounts", "/nats-accounts", needs = "project_id",
                "NATS accounts and their endpoints.", [
                check!(Medium, "mnq.nats-accounts.shared", "one account shared by unrelated services, which makes every subject reachable by all of them"),
            ]),
        ],
    },
    Product {
        key: "domain",
        name: "Domains and DNS",
        base: "/domain/v2beta1",
        scope: Scope::Global,
        paging: Paging::Page,
        permission: "DomainsDNSReadOnly",
        about: "The names that point at everything above. DNS is where an audit finds \
                the resources nobody remembered to tell it about.",
        resources: &[
            res!("domains", "/domains",
                "Registration status, expiry, DNSSEC and auto-renew.", [
                check!(Critical, "domain.domains.expiring", "expiring inside 30 days without auto-renew: the whole estate depends on a payment nobody is watching"),
                check!(High, "domain.domains.no-dnssec", "DNSSEC off on a domain used for authentication or mail"),
                check!(Medium, "domain.domains.external", "registered elsewhere but served here, so two parties can change what it means"),
            ]),
            res!("dns-zones", "/dns-zones",
                "The zones and their nameservers.", [
                check!(High, "domain.dns-zones.lame-delegation", "a subdomain delegated to nameservers that no longer answer for it"),
            ]),
            res!("records", "/dns-zones/{id}/records", parent = "dns-zones",
                "Every record. Cross-referenced with the address inventory, this is the takeover check.", [
                check!(Critical, "domain.records.dangling-cname", "a CNAME or A record pointing at a bucket, load balancer or address the account no longer holds: subdomain takeover, and the first step of a convincing phish"),
                check!(High, "domain.records.no-caa", "no CAA record, so any certificate authority may issue for the name"),
                check!(High, "domain.records.spf-weak", "an SPF record ending in ?all or +all, or with more than ten lookups"),
                check!(High, "domain.records.dmarc-none", "a DMARC policy of none, or no DMARC at all: the domain can be spoofed and you will not hear about it"),
                check!(Medium, "domain.records.wildcard", "a wildcard record, which answers for names nobody created"),
                check!(Low, "domain.records.long-ttl", "a TTL long enough to make an incident response slow"),
            ]),
            res!("ssl-certificates", "/ssl-certificates",
                "Managed certificates for zones. The private key is in this response — the \
                 reason `wiki/Secrets.md` exists.", [
                check!(Critical, "domain.ssl-certificates.private-key-readable", "a read call returns the certificate's private key, so DomainsDNSReadOnly is impersonation of the site"),
                check!(High, "domain.ssl-certificates.expiring", "expired_at inside 30 days"),
            ]),
        ],
    },
    Product {
        key: "tem",
        name: "Transactional Email",
        base: "/transactional-email/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "TransactionalEmailReadOnly",
        about: "Sending domains, their SPF and DKIM state, and their reputation.",
        resources: &[
            res!("domains", "/domains",
                "Verification state, SPF and DKIM configuration, reputation.", [
                check!(High, "tem.domains.unverified-active", "a domain left in a partially verified state while still configured to send"),
                check!(High, "tem.domains.reputation", "a falling reputation score, which is what a compromised sending key looks like from outside"),
                check!(Medium, "tem.domains.revoked", "revoked but not removed"),
            ]),
            res!("webhooks", "/webhooks",
                "Where delivery events are sent.", [
                check!(Medium, "tem.webhooks.foreign-sns", "an SNS destination outside the organization"),
            ]),
        ],
    },
    Product {
        key: "webhosting",
        name: "Web Hosting",
        base: "/webhosting/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "WebHostingReadOnly",
        about: "Shared hosting: FTP accounts, mailboxes and databases, all in one place.",
        resources: &[
            res!("hostings", "/hostings",
                "The hostings, their DNS state and their protection.", [
                check!(High, "webhosting.hostings.dns-mismatch", "dns_status not valid: the site is served from somewhere else, or not at all"),
                check!(Medium, "webhosting.hostings.unprotected", "protected=false"),
            ]),
            res!("ftp-accounts", "/hostings/{id}/ftp-accounts", parent = "hostings",
                "FTP logins and the paths they reach.", [
                check!(High, "webhosting.ftp-accounts.docroot", "an account whose path is the document root, so a leaked password is a site defacement"),
                check!(Medium, "webhosting.ftp-accounts.unused", "an account nobody has used since the site was built"),
            ]),
        ],
    },
    // ---- observability, IoT, AI, spend -------------------------------------
    Product {
        key: "cockpit",
        name: "Cockpit",
        base: "/cockpit/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "ObservabilityReadOnly",
        about: "Metrics, logs and alerting. Not a finding in itself — but an account with \
                no alerting is an account where every other finding stays true for months. \
                Every call here is project-scoped and requires a project_id, so a sweep \
                narrowed to one project reports nothing at all about the others.",
        resources: &[
            one!("alert-manager", "/alert-manager", needs = "project_id",
                "Whether alerting is switched on at all.", [
                check!(High, "cockpit.alert-manager.off", "alert_manager_enabled=false: nothing in the account will ever tell you something is wrong"),
                check!(Medium, "cockpit.alert-manager.no-managed-alerts", "the preconfigured alerts left off"),
            ]),
            res!("contact-points", "/alert-manager/contact-points", needs = "project_id",
                "Who receives an alert.", [
                check!(High, "cockpit.contact-points.none", "alerting on, with nowhere to send it"),
                check!(Medium, "cockpit.contact-points.personal", "one person's address as the only destination"),
            ]),
            res!("tokens", "/tokens", needs = "project_id",
                "Ingestion and query tokens, and their scopes.", [
                check!(High, "cockpit.tokens.query-scope", "a token that can read logs handed to a component that only needs to write them"),
            ]),
            res!("grafana-users", "/grafana/users",
                "Dashboard accounts and their roles.", [
                check!(Medium, "cockpit.grafana-users.editors", "editor or admin where viewer would do"),
            ]),
            res!("data-sources", "/data-sources", needs = "project_id",
                "Retention, per data source.", [
                check!(High, "cockpit.data-sources.short-retention", "a log retention shorter than the time it typically takes to notice a breach"),
            ]),
        ],
    },
    Product {
        key: "audit-trail",
        name: "Audit Trail",
        base: "/audit-trail/v1alpha1",
        scope: Scope::Region,
        paging: Paging::Token,
        permission: "AuditTrailReadOnly",
        about: "What was actually done, by whom, from where. Every other product in this \
                catalogue describes a state; this one describes the changes that produced it.",
        resources: &[
            res!("events", "/events", needs = "organization_id",
                "API calls that changed something, with principal, source address and status.", [
                check!(High, "audit-trail.events.iam-changes", "policy, key and membership changes: the shortest path from a foothold to persistence"),
                check!(High, "audit-trail.events.off-hours", "writes outside working hours from an address that has done nothing else"),
                check!(Medium, "audit-trail.events.deletions", "deletions of logs, snapshots or backups, in that order, which is the classic sequence"),
                check!(Info, "audit-trail.events.coverage", "the earliest event available, which is the honest limit of any answer given here"),
            ]),
            res!("authentication-events", "/authentication-events", needs = "organization_id",
                "Logins, their result, their country and their MFA method.", [
                check!(Critical, "audit-trail.authentication-events.success-after-failures", "a successful login after a run of failures, from a country the account has never seen"),
                check!(High, "audit-trail.authentication-events.no-mfa", "successful logins with no MFA method recorded"),
                check!(Medium, "audit-trail.authentication-events.new-country", "a first login from a new country"),
            ]),
        ],
    },
    Product {
        key: "iot",
        name: "IoT Hub",
        base: "/iot/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "IoTReadOnly",
        about: "Device fleets. The devices are outside your building and the hub decides \
                how much it trusts them.",
        resources: &[
            res!("hubs", "/hubs",
                "Auto-provisioning, custom CA and event configuration.", [
                check!(Critical, "iot.hubs.auto-provisioning", "enable_device_auto_provisioning: anything that connects becomes a device"),
                check!(High, "iot.hubs.no-custom-ca", "no custom certificate authority, so device identity rests on what the platform issues to anyone"),
                check!(Medium, "iot.hubs.events-disabled", "disable_events, which removes the only record of what the fleet did"),
            ]),
            res!("devices", "/devices",
                "Per-device trust settings.", [
                check!(Critical, "iot.devices.allow-insecure", "allow_insecure: the device may connect without TLS, and so may anything claiming to be it"),
                check!(High, "iot.devices.shared-identity", "allow_multiple_connections, which is how one leaked certificate becomes a fleet"),
                check!(Medium, "iot.devices.dormant", "no activity for months, still authorized"),
            ]),
            res!("routes", "/routes",
                "Where device messages are forwarded: S3, a database, or an HTTP endpoint.", [
                check!(High, "iot.routes.foreign-endpoint", "a REST route to a host outside the account, carrying device data off-platform"),
            ]),
        ],
    },
    Product {
        key: "inference",
        name: "Managed Inference",
        base: "/inference/v1",
        scope: Scope::Region,
        paging: Paging::Page,
        permission: "InferenceReadOnly",
        about: "Model endpoints, which are expensive and occasionally unauthenticated.",
        resources: &[
            res!("deployments", "/deployments",
                "Endpoints, and whether they ask for a token.", [
                check!(Critical, "inference.deployments.no-auth", "disable_auth on a public_network endpoint: a GPU endpoint anyone can drive, billed to you"),
                check!(Medium, "inference.deployments.idle", "a deployment with a non-zero floor and no traffic"),
            ]),
        ],
    },
    Product {
        key: "billing",
        name: "Billing",
        base: "/billing/v2beta1",
        scope: Scope::Global,
        paging: Paging::Page,
        permission: "BillingReadOnly",
        about: "Spend, read as a detector rather than as an invoice: mining, exfiltration \
                and forgotten resources all show up here before they show up anywhere else.",
        resources: &[
            res!("consumptions", "/consumptions", needs = "organization_id",
                "Current consumption, by category and project.", [
                check!(High, "billing.consumptions.spike", "a category jumping against its own baseline — the earliest signal of a stolen key that most accounts actually have"),
                check!(Medium, "billing.consumptions.egress", "an Object Storage egress line that does not match the traffic you serve"),
                check!(Medium, "billing.consumptions.idle", "spend in a project with no recent audit-trail activity"),
            ]),
            res!("invoices", "/invoices", needs = "organization_id",
                "Historical invoices, for the baseline the check above needs.", [
                check!(Info, "billing.invoices.baseline", "twelve months of spend, which is what makes a spike a spike"),
            ]),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_product_key_and_check_id_is_unique() {
        let mut keys = HashSet::new();
        let mut ids = HashSet::new();
        for p in PRODUCTS {
            assert!(keys.insert(p.key), "duplicate product key {}", p.key);
            let mut rkeys = HashSet::new();
            for r in p.resources {
                assert!(
                    rkeys.insert(r.key),
                    "duplicate resource {}/{}",
                    p.key,
                    r.key
                );
                for c in r.checks {
                    assert!(ids.insert(c.id), "duplicate check id {}", c.id);
                }
            }
        }
    }

    #[test]
    fn a_check_id_names_the_product_and_resource_it_belongs_to() {
        for p in PRODUCTS {
            for r in p.resources {
                for c in r.checks {
                    let prefix = format!("{}.{}.", p.key, r.key);
                    assert!(
                        c.id.starts_with(&prefix),
                        "{} should start with {prefix}",
                        c.id
                    );
                }
            }
        }
    }

    #[test]
    fn every_parent_reference_resolves_and_the_path_takes_an_id() {
        for p in PRODUCTS {
            for r in p.resources {
                match r.parent {
                    Some(parent) => {
                        assert!(
                            p.resources.iter().any(|o| o.key == parent)
                                || parent == "organizations",
                            "{}/{} names an unknown parent {parent}",
                            p.key,
                            r.key
                        );
                        // Scaleway expresses "one of these per that" two ways,
                        // and both are real: a path segment (security-group
                        // rules) or a required query parameter (`policy_id` on
                        // IAM rules, `audience_id` on JWTs). A parent needs one
                        // or the other, not specifically a path segment.
                        assert!(
                            r.path.contains("{id}") || !r.needs.is_empty(),
                            "{}/{} has a parent but no place to put its id",
                            p.key,
                            r.key
                        );
                    }
                    None => assert!(
                        !r.path.contains("{id}"),
                        "{}/{} needs an id and has no parent to take it from",
                        p.key,
                        r.key
                    ),
                }
            }
        }
    }

    #[test]
    fn a_needed_parameter_is_named_rather_than_described() {
        // The names are what a caller has to put in a query string, so a typo
        // here is a 400 at run time on a real account.
        const KNOWN: [&str; 4] = ["organization_id", "project_id", "policy_id", "audience_id"];
        for p in PRODUCTS {
            for r in p.resources {
                assert!(
                    r.needs.is_empty() || KNOWN.contains(&r.needs),
                    "{}/{} needs {:?}, which is not a parameter this API takes",
                    p.key,
                    r.key,
                    r.needs
                );
            }
        }
    }

    #[test]
    fn every_base_is_a_versioned_absolute_path() {
        for p in PRODUCTS {
            assert!(p.base.starts_with('/'), "{}", p.base);
            assert!(!p.base.ends_with('/'), "{}", p.base);
            let version = p.base.rsplit('/').next().unwrap();
            assert!(version.starts_with('v'), "{} is not versioned", p.base);
        }
    }

    #[test]
    fn a_path_is_assembled_from_base_locality_and_resource() {
        let instance = product("instance").unwrap();
        let servers = instance
            .resources
            .iter()
            .find(|r| r.key == "servers")
            .unwrap();
        assert_eq!(
            instance.path_of(servers, "fr-par-1"),
            "/instance/v1/zones/fr-par-1/servers"
        );

        let iam = product("iam").unwrap();
        let users = iam.resources.iter().find(|r| r.key == "users").unwrap();
        assert_eq!(iam.path_of(users, ""), "/iam/v1alpha1/users");
    }

    #[test]
    fn the_permission_sets_needed_are_all_read_only() {
        let sets = permission_sets();
        assert!(!sets.is_empty());
        for s in &sets {
            assert!(
                s.ends_with("ReadOnly"),
                "{s} is not a read-only permission set"
            );
        }
        assert!(sets.windows(2).all(|w| w[0] < w[1]), "sorted and deduped");
    }

    #[test]
    fn severities_order_worst_first() {
        let mut v = vec![Severity::Low, Severity::Critical, Severity::Medium];
        v.sort();
        assert_eq!(v, vec![Severity::Critical, Severity::Medium, Severity::Low]);
    }
}
