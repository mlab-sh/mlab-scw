//! Fixtures are the shapes the real API returns, with every identifier
//! invented.

use super::*;
use crate::scw::sweep::{Fetch, Fetched};
use crate::scw::Paging;
use serde_json::json;

const NOW: i64 = 1_800_000_000;

fn got(
    product: &'static str,
    resource: &'static str,
    locality: &str,
    items: Vec<Value>,
) -> Fetched {
    Fetched {
        fetch: Fetch::new(
            product,
            resource,
            locality,
            format!("/{product}/{resource}"),
        ),
        items,
        gap: None,
    }
}

/// A second-round fetch, whose parent id lives in the path.
fn under(
    product: &'static str,
    resource: &'static str,
    locality: &str,
    parent: &str,
    items: Vec<Value>,
) -> Fetched {
    Fetched {
        fetch: Fetch::new(
            product,
            resource,
            locality,
            format!("/{product}/{parent}/{resource}"),
        )
        .paging(Paging::Page),
        items,
        gap: None,
    }
}

fn ids(f: &[Finding]) -> Vec<&str> {
    f.iter().map(|x| x.id).collect()
}

fn has(f: &[Finding], id: &str) -> bool {
    f.iter().any(|x| x.id == id)
}

// ---- the join that is the point of the command ------------------------------

#[test]
fn one_public_server_is_two_different_findings_depending_on_what_is_in_front() {
    let server = json!({
        "id": "s1", "name": "web", "public_ip": {"address": "203.0.113.10"},
        "security_group": {"id": "g1", "name": "web-sg"}
    });

    // Same server, same address. The only difference is the group's default.
    let open = vec![
        got("instance", "servers", "fr-par-1", vec![server.clone()]),
        got(
            "instance",
            "security-groups",
            "fr-par-1",
            vec![json!({"id": "g1", "name": "web-sg", "inbound_default_policy": "accept"})],
        ),
    ];
    let shut = vec![
        got("instance", "servers", "fr-par-1", vec![server]),
        got(
            "instance",
            "security-groups",
            "fr-par-1",
            vec![json!({"id": "g1", "name": "web-sg", "inbound_default_policy": "drop"})],
        ),
    ];

    let e = Edge::new(&open);
    assert!(has(&e.audit(NOW), "instance.servers.public-no-filter"));
    assert_eq!(e.exposures()[0].control.verdict(), "open");

    let e = Edge::new(&shut);
    assert!(!has(&e.audit(NOW), "instance.servers.public-no-filter"));
    assert_eq!(
        e.exposures()[0].control.verdict(),
        "narrowed",
        "an address behind a closed default is still an exposure, just not an open one"
    );
}

#[test]
fn a_security_group_that_could_not_be_read_is_unknown_rather_than_guessed() {
    // Reporting an unread control as open invents a critical finding; reporting
    // it as narrowed hides one. Neither is acceptable, so it says so.
    let sweep = vec![got(
        "instance",
        "servers",
        "fr-par-1",
        vec![
            json!({"id": "s1", "name": "web", "public_ip": {"address": "203.0.113.10"},
                    "security_group": {"id": "g1", "name": "web-sg"}}),
        ],
    )];
    let e = Edge::new(&sweep);
    assert_eq!(e.exposures()[0].control, Control::Unknown);
    assert!(!has(&e.audit(NOW), "instance.servers.public-no-filter"));
}

#[test]
fn a_server_with_no_public_address_is_not_an_exposure() {
    let sweep = vec![got(
        "instance",
        "servers",
        "fr-par-1",
        vec![
            json!({"id": "s1", "name": "internal", "private_ip": "10.0.0.4",
                    "public_ip": null, "public_ips": []}),
        ],
    )];
    assert!(Edge::new(&sweep).exposures().is_empty());
}

// ---- security group rules ---------------------------------------------------

#[test]
fn a_world_rule_is_graded_by_what_the_range_actually_covers() {
    let group = json!({"id": "g1", "name": "sg", "inbound_default_policy": "drop"});
    let rule = |from: i64, to: i64| {
        json!({"direction": "inbound", "action": "accept", "ip_range": "0.0.0.0/0",
               "dest_port_from": from, "dest_port_to": to})
    };

    let sweep = vec![
        got(
            "instance",
            "security-groups",
            "fr-par-1",
            vec![group.clone()],
        ),
        under(
            "instance",
            "security-group-rules",
            "fr-par-1",
            "g1",
            vec![rule(22, 22)],
        ),
    ];
    let f = Edge::new(&sweep).audit(NOW);
    assert!(has(&f, "instance.security-group-rules.world-ssh"));
    assert!(f[0].detail.contains("SSH"));

    let sweep = vec![
        got(
            "instance",
            "security-groups",
            "fr-par-1",
            vec![group.clone()],
        ),
        under(
            "instance",
            "security-group-rules",
            "fr-par-1",
            "g1",
            vec![rule(8080, 8080)],
        ),
    ];
    let f = Edge::new(&sweep).audit(NOW);
    assert!(has(&f, "instance.security-group-rules.world-any"));
    assert!(!has(&f, "instance.security-group-rules.world-ssh"));

    // A wide range that happens to swallow 22 is the same problem as naming it.
    let sweep = vec![
        got("instance", "security-groups", "fr-par-1", vec![group]),
        under(
            "instance",
            "security-group-rules",
            "fr-par-1",
            "g1",
            vec![rule(1, 1024)],
        ),
    ];
    assert!(has(
        &Edge::new(&sweep).audit(NOW),
        "instance.security-group-rules.world-ssh"
    ));
}

#[test]
fn a_rule_that_is_not_world_facing_or_not_an_accept_is_left_alone() {
    let group = json!({"id": "g1", "name": "sg", "inbound_default_policy": "drop"});
    let sweep = vec![
        got("instance", "security-groups", "fr-par-1", vec![group]),
        under(
            "instance",
            "security-group-rules",
            "fr-par-1",
            "g1",
            vec![
                json!({"direction": "inbound", "action": "accept", "ip_range": "198.51.100.0/24",
                       "dest_port_from": 22, "dest_port_to": 22}),
                json!({"direction": "inbound", "action": "drop", "ip_range": "0.0.0.0/0",
                       "dest_port_from": 22, "dest_port_to": 22}),
                json!({"direction": "outbound", "action": "accept", "ip_range": "0.0.0.0/0"}),
            ],
        ),
    ];
    let f = Edge::new(&sweep).audit(NOW);
    assert!(!has(&f, "instance.security-group-rules.world-ssh"));
    assert!(!has(&f, "instance.security-group-rules.world-any"));
}

// ---- databases --------------------------------------------------------------

#[test]
fn a_private_network_endpoint_is_not_a_public_one() {
    let private = json!({"id": "d1", "name": "db", "endpoints": [
        {"ip": "10.0.0.5", "port": 5432, "private_network": {"private_network_id": "pn1"}}]});
    let public = json!({"id": "d2", "name": "db-pub", "endpoints": [
        {"hostname": "db.example", "port": 5432, "load_balancer": {}}]});

    let sweep = vec![got("rdb", "instances", "fr-par", vec![private])];
    assert!(Edge::new(&sweep).exposures().is_empty());
    assert!(!has(
        &Edge::new(&sweep).audit(NOW),
        "rdb.instances.public-endpoint"
    ));

    let sweep = vec![got("rdb", "instances", "fr-par", vec![public])];
    let e = Edge::new(&sweep);
    assert_eq!(e.exposures().len(), 1);
    assert!(has(&e.audit(NOW), "rdb.instances.public-endpoint"));
}

#[test]
fn a_database_acl_of_anywhere_is_the_same_as_no_acl() {
    let inst = json!({"id": "d1", "name": "db",
                      "endpoints": [{"hostname": "db.example", "port": 5432, "load_balancer": {}}]});
    let narrow = vec![
        got("rdb", "instances", "fr-par", vec![inst.clone()]),
        under(
            "rdb",
            "acls",
            "fr-par",
            "d1",
            vec![json!({"ip": "198.51.100.0/24"})],
        ),
    ];
    let wide = vec![
        got("rdb", "instances", "fr-par", vec![inst]),
        under(
            "rdb",
            "acls",
            "fr-par",
            "d1",
            vec![json!({"ip": "0.0.0.0/0"})],
        ),
    ];

    let e = Edge::new(&narrow);
    assert!(!has(&e.audit(NOW), "rdb.acls.world"));
    assert_eq!(e.exposures()[0].control.verdict(), "narrowed");

    let e = Edge::new(&wide);
    assert!(has(&e.audit(NOW), "rdb.acls.world"));
    assert_eq!(e.exposures()[0].control.verdict(), "open");
}

#[test]
fn redis_without_tls_is_a_finding_whether_or_not_it_is_public() {
    let sweep = vec![got(
        "redis",
        "clusters",
        "fr-par-1",
        vec![json!({"id": "r1", "name": "cache", "tls_enabled": false,
                    "endpoints": [{"port": 6379, "private_network": {}}]})],
    )];
    let f = Edge::new(&sweep).audit(NOW);
    assert!(has(&f, "redis.clusters.no-tls"));
    assert!(!has(&f, "redis.clusters.public-no-acl"), "it is not public");
}

// ---- gateways ---------------------------------------------------------------

#[test]
fn a_bastion_is_only_a_finding_when_nothing_narrows_it() {
    let open = vec![got(
        "vpc-gw",
        "gateways",
        "fr-par-1",
        vec![
            json!({"id": "g1", "name": "gw", "ipv4": {"address": "203.0.113.20"},
                    "bastion_enabled": true, "bastion_port": 61000,
                    "bastion_allowed_ips": []}),
        ],
    )];
    let narrowed = vec![got(
        "vpc-gw",
        "gateways",
        "fr-par-1",
        vec![
            json!({"id": "g1", "name": "gw", "ipv4": {"address": "203.0.113.20"},
                    "bastion_enabled": true, "bastion_port": 61000,
                    "bastion_allowed_ips": ["198.51.100.0/24"]}),
        ],
    )];
    assert!(has(
        &Edge::new(&open).audit(NOW),
        "vpc-gw.gateways.bastion-open"
    ));
    assert!(!has(
        &Edge::new(&narrowed).audit(NOW),
        "vpc-gw.gateways.bastion-open"
    ));
    assert_eq!(
        Edge::new(&narrowed).exposures()[0].control.verdict(),
        "narrowed"
    );
}

#[test]
fn a_port_forward_is_judged_on_both_ends() {
    // 2222 on the outside, 22 on the inside, is still SSH published to the
    // internet — and a forward from 22 to 2222 is the same thing backwards.
    for (public, private) in [(2222, 22), (22, 2222)] {
        let sweep = vec![got(
            "vpc-gw",
            "pat-rules",
            "fr-par-1",
            vec![json!({"gateway_id": "g1", "public_port": public,
                        "private_port": private, "private_ip": "10.0.0.4"})],
        )];
        let f = Edge::new(&sweep).audit(NOW);
        assert!(
            has(&f, "vpc-gw.pat-rules.admin-port"),
            "{public} -> {private} publishes SSH"
        );
    }

    let sweep = vec![got(
        "vpc-gw",
        "pat-rules",
        "fr-par-1",
        vec![json!({"gateway_id": "g1", "public_port": 8080,
                    "private_port": 8080, "private_ip": "10.0.0.4"})],
    )];
    assert!(!has(
        &Edge::new(&sweep).audit(NOW),
        "vpc-gw.pat-rules.admin-port"
    ));
}

// ---- kubernetes -------------------------------------------------------------

#[test]
fn a_control_plane_with_no_allow_list_and_one_with_the_world_in_it_both_count() {
    let cluster = json!({"id": "c1", "name": "prod",
                         "cluster_url": "https://c1.api.k8s.fr-par.scw.cloud"});
    let bare = vec![got("k8s", "clusters", "fr-par", vec![cluster.clone()])];
    assert!(has(
        &Edge::new(&bare).audit(NOW),
        "k8s.clusters.public-apiserver-no-acl"
    ));

    let world = vec![
        got("k8s", "clusters", "fr-par", vec![cluster.clone()]),
        under(
            "k8s",
            "acls",
            "fr-par",
            "c1",
            vec![json!({"ip": "0.0.0.0/0"})],
        ),
    ];
    let f = Edge::new(&world).audit(NOW);
    assert!(has(&f, "k8s.acls.world"));
    assert!(
        !has(&f, "k8s.clusters.public-apiserver-no-acl"),
        "there is an allow-list; it is just useless, which is the other finding"
    );

    let narrow = vec![
        got("k8s", "clusters", "fr-par", vec![cluster]),
        under(
            "k8s",
            "acls",
            "fr-par",
            "c1",
            vec![json!({"ip": "198.51.100.0/24"})],
        ),
    ];
    let f = Edge::new(&narrow).audit(NOW);
    assert!(
        f.is_empty(),
        "a narrowed control plane is not a finding: {:?}",
        ids(&f)
    );
}

// ---- serverless and registries ----------------------------------------------

#[test]
fn only_a_public_serverless_endpoint_is_reported() {
    let sweep = vec![got(
        "containers",
        "containers",
        "fr-par",
        vec![
            json!({"id": "c1", "name": "api", "privacy": "public",
                   "domain_name": "api.example.functions.fnc.fr-par.scw.cloud"}),
            json!({"id": "c2", "name": "worker", "privacy": "private",
                   "domain_name": "worker.example.functions.fnc.fr-par.scw.cloud"}),
        ],
    )];
    let e = Edge::new(&sweep);
    let f = e.audit(NOW);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].id, "containers.containers.public");
    assert!(f[0].subject.starts_with("api"));
    assert_eq!(e.exposures().len(), 1);
}

#[test]
fn a_public_registry_namespace_is_an_exposure_of_every_image_in_it() {
    let sweep = vec![got(
        "registry",
        "namespaces",
        "fr-par",
        vec![
            json!({"id": "n1", "name": "public-ns", "is_public": true,
                   "endpoint": "rg.fr-par.scw.cloud/public-ns", "image_count": 4}),
            json!({"id": "n2", "name": "private-ns", "is_public": false,
                   "endpoint": "rg.fr-par.scw.cloud/private-ns", "image_count": 9}),
        ],
    )];
    let e = Edge::new(&sweep).exposures();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].kind, "registry");
    assert_eq!(e[0].control.verdict(), "open");
}

// ---- addresses --------------------------------------------------------------

#[test]
fn an_address_attached_to_nothing_is_a_finding_and_an_attached_one_is_not() {
    let sweep = vec![got(
        "instance",
        "ips",
        "fr-par-1",
        vec![
            json!({"id": "i1", "address": "203.0.113.30", "server": null}),
            json!({"id": "i2", "address": "203.0.113.31", "server": {"id": "s1"}}),
        ],
    )];
    let f = Edge::new(&sweep).audit(NOW);
    let dangling: Vec<&Finding> = f
        .iter()
        .filter(|x| x.id == "instance.ips.dangling")
        .collect();
    assert_eq!(dangling.len(), 1);
    assert!(dangling[0].subject.starts_with("203.0.113.30"));
}

// ---- the whole thing --------------------------------------------------------

#[test]
fn an_account_with_nothing_public_produces_nothing() {
    let sweep = vec![
        got("instance", "servers", "fr-par-1", vec![]),
        got("lb", "lbs", "fr-par-1", vec![]),
        got("k8s", "clusters", "fr-par", vec![]),
    ];
    let e = Edge::new(&sweep);
    assert!(e.exposures().is_empty());
    assert!(e.audit(NOW).is_empty());
}

#[test]
fn exposures_are_ordered_open_first() {
    let sweep = vec![
        got(
            "registry",
            "namespaces",
            "fr-par",
            vec![json!({"id": "n1", "name": "pub", "is_public": true, "endpoint": "rg/pub"})],
        ),
        got(
            "rdb",
            "instances",
            "fr-par",
            vec![json!({"id": "d1", "name": "db",
                        "endpoints": [{"hostname": "db", "port": 5432, "load_balancer": {}}]})],
        ),
        under(
            "rdb",
            "acls",
            "fr-par",
            "d1",
            vec![json!({"ip": "198.51.100.0/24"})],
        ),
    ];
    let e = Edge::new(&sweep).exposures();
    assert_eq!(e[0].control.verdict(), "open");
    assert_eq!(e[1].control.verdict(), "narrowed");
}

/// One account carrying every exposure this module knows how to find, so the
/// ids it emits can be compared against the ids it claims to emit.
fn everything() -> Vec<Fetched> {
    vec![
        got(
            "instance",
            "servers",
            "fr-par-1",
            vec![
                json!({"id": "s1", "name": "web", "public_ip": {"address": "203.0.113.10"},
                        "security_group": {"id": "g1", "name": "default"}}),
            ],
        ),
        got(
            "instance",
            "security-groups",
            "fr-par-1",
            vec![
                json!({"id": "g1", "name": "default", "inbound_default_policy": "accept",
                        "project_default": true}),
            ],
        ),
        under(
            "instance",
            "security-group-rules",
            "fr-par-1",
            "g1",
            vec![
                json!({"direction": "inbound", "action": "accept", "ip_range": "0.0.0.0/0",
                       "dest_port_from": 22, "dest_port_to": 22}),
                json!({"direction": "inbound", "action": "accept", "ip_range": "0.0.0.0/0",
                       "dest_port_from": 8080, "dest_port_to": 8080}),
            ],
        ),
        got(
            "instance",
            "ips",
            "fr-par-1",
            vec![json!({"id": "i1", "address": "203.0.113.30", "server": null})],
        ),
        got(
            "baremetal",
            "servers",
            "fr-par-2",
            vec![
                json!({"id": "b1", "name": "metal", "ips": [{"address": "203.0.113.40",
                        "version": "IPv4"}], "rescue_server": {"user": "root"}}),
            ],
        ),
        got("baremetal", "server-private-networks", "fr-par-2", vec![]),
        got(
            "apple-silicon",
            "servers",
            "fr-par-3",
            vec![json!({"id": "m1", "name": "mac", "ip": "203.0.113.50",
                        "vnc_url": "vnc://203.0.113.50:5900", "vnc_port": 5900})],
        ),
        got(
            "flexible-ip",
            "fips",
            "fr-par-2",
            vec![json!({"id": "f1", "ip_address": "203.0.113.60", "server_id": null})],
        ),
        got(
            "ipam",
            "ips",
            "fr-par",
            vec![
                json!({"id": "p1", "address": "203.0.113.70/32", "source": {"zonal": "fr-par-1"},
                       "resource": {"id": "s1"}}),
                json!({"id": "p2", "address": "203.0.113.71/32", "source": {"zonal": "fr-par-1"},
                       "resource": null}),
            ],
        ),
        got(
            "lb",
            "lbs",
            "fr-par-1",
            vec![json!({"id": "l1", "name": "front", "ip": [{"ip_address": "203.0.113.80"}]})],
        ),
        under(
            "lb",
            "certificates",
            "fr-par-1",
            "l1",
            vec![
                json!({"id": "cert-old", "name": "expired-cert",
                       "not_valid_after": "2020-01-01T00:00:00Z"}),
                json!({"id": "cert-soon", "name": "expiring-cert",
                       "not_valid_after": "2027-01-25T00:00:00Z"}),
            ],
        ),
        under(
            "lb",
            "frontends",
            "fr-par-1",
            "l1",
            vec![
                json!({"id": "fe1", "name": "http", "inbound_port": 80}),
                json!({"id": "fe2", "name": "https", "inbound_port": 443}),
            ],
        ),
        got(
            "lb",
            "ips",
            "fr-par-1",
            vec![json!({"id": "lip", "ip_address": "203.0.113.81", "lb": null})],
        ),
        got(
            "vpc-gw",
            "gateways",
            "fr-par-1",
            vec![
                json!({"id": "gw1", "name": "gw", "ipv4": {"address": "203.0.113.90"},
                        "bastion_enabled": true, "bastion_port": 61000,
                        "bastion_allowed_ips": []}),
            ],
        ),
        got(
            "vpc-gw",
            "pat-rules",
            "fr-par-1",
            vec![
                json!({"gateway_id": "gw1", "public_port": 2222, "private_port": 22,
                        "private_ip": "10.0.0.4"}),
            ],
        ),
        got(
            "k8s",
            "clusters",
            "fr-par",
            vec![
                json!({"id": "c1", "name": "no-acl",
                       "cluster_url": "https://c1.api.k8s.fr-par.scw.cloud"}),
                json!({"id": "c2", "name": "world-acl",
                       "cluster_url": "https://c2.api.k8s.fr-par.scw.cloud"}),
            ],
        ),
        under(
            "k8s",
            "acls",
            "fr-par",
            "c2",
            vec![json!({"ip": "0.0.0.0/0"})],
        ),
        got(
            "k8s",
            "pools",
            "fr-par",
            vec![json!({"id": "pool1", "name": "workers", "public_ip_disabled": false})],
        ),
        got(
            "rdb",
            "instances",
            "fr-par",
            vec![json!({"id": "d1", "name": "db",
                        "endpoints": [{"hostname": "db.example", "port": 5432,
                                       "load_balancer": {}}]})],
        ),
        under(
            "rdb",
            "acls",
            "fr-par",
            "d1",
            vec![json!({"ip": "0.0.0.0/0"})],
        ),
        got(
            "redis",
            "clusters",
            "fr-par-1",
            vec![
                json!({"id": "r1", "name": "cache", "tls_enabled": false, "acl_rules": [],
                        "endpoints": [{"port": 6379, "public_network": {},
                                       "ips": ["203.0.113.100"]}]}),
            ],
        ),
        got(
            "containers",
            "containers",
            "fr-par",
            vec![json!({"id": "ct1", "name": "api", "privacy": "public",
                        "domain_name": "api.example.scw.cloud"})],
        ),
        got(
            "functions",
            "functions",
            "fr-par",
            vec![json!({"id": "fn1", "name": "hook", "privacy": "public",
                        "domain_name": "hook.example.scw.cloud"})],
        ),
    ]
}

#[test]
fn the_module_emits_exactly_what_it_claims_to_emit() {
    // Two checks were declared in IMPLEMENTED and never written. Nothing failed;
    // the report simply never mentioned an exposed Elastic Metal server or a
    // public VNC endpoint. A list of ids is not a guarantee — this is.
    use std::collections::BTreeSet;
    let sweep = everything();
    let emitted: BTreeSet<&str> = Edge::new(&sweep).audit(NOW).iter().map(|f| f.id).collect();
    let claimed: BTreeSet<&str> = IMPLEMENTED.into_iter().collect();

    let unclaimed: Vec<&&str> = emitted.difference(&claimed).collect();
    assert!(
        unclaimed.is_empty(),
        "emitted but not in IMPLEMENTED: {unclaimed:?}"
    );

    let unreachable: Vec<&&str> = claimed.difference(&emitted).collect();
    assert!(
        unreachable.is_empty(),
        "claimed in IMPLEMENTED but never emitted by an account carrying every exposure: \
         {unreachable:?}"
    );
}

#[test]
fn a_certificate_is_graded_by_how_long_is_left_rather_than_by_a_flag() {
    let sweep = vec![
        got(
            "lb",
            "lbs",
            "fr-par-1",
            vec![json!({"id": "l1", "name": "front",
                                                 "ip": [{"ip_address": "203.0.113.80"}]})],
        ),
        under(
            "lb",
            "certificates",
            "fr-par-1",
            "l1",
            vec![
                json!({"id": "c1", "name": "gone", "not_valid_after": "2020-01-01T00:00:00Z"}),
                json!({"id": "c2", "name": "soon", "not_valid_after": "2027-01-25T00:00:00Z"}),
                json!({"id": "c3", "name": "fine", "not_valid_after": "2029-01-01T00:00:00Z"}),
                json!({"id": "c4", "name": "unknown"}),
            ],
        ),
    ];
    let f = Edge::new(&sweep).audit(NOW);
    let expired: Vec<&Finding> = f
        .iter()
        .filter(|x| x.id == "lb.certificates.expired")
        .collect();
    let expiring: Vec<&Finding> = f
        .iter()
        .filter(|x| x.id == "lb.certificates.expiring")
        .collect();
    assert_eq!(expired.len(), 1, "one is past its date");
    assert!(expired[0].detail.starts_with("expired"));
    assert_eq!(expiring.len(), 1, "one is inside the window");
    assert!(
        expiring[0].detail.starts_with("expires in"),
        "{}",
        expiring[0].detail
    );
}

#[test]
fn every_id_this_module_emits_exists_in_the_catalogue() {
    let mut catalogued: Vec<&str> = Vec::new();
    for p in crate::scw::catalog::PRODUCTS {
        for r in p.resources {
            for c in r.checks {
                catalogued.push(c.id);
            }
        }
    }
    for id in IMPLEMENTED {
        assert!(
            catalogued.contains(&id),
            "{id} is emitted but not catalogued"
        );
    }
}
