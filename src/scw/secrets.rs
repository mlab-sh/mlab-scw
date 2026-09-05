//! The fields that must never be written to disk, and how to remove them.
//!
//! One list, used by everything that persists an API response, so a field
//! cannot be redacted in one place and stored in another.
//!
//! Every name here is one a *read* call returns. That is the point of the list:
//! a key with nothing but `…ReadOnly` permission sets still receives an Apple
//! silicon `sudo_password`, a Dedibox `bmc-access` login, a Domains SSL
//! `private_key` and an EPP transfer `auth_code`. See `wiki/Secrets.md`.

use serde_json::Value;

/// Field names holding an actual secret, as returned by a GET.
///
/// Deliberately an explicit list rather than a substring rule. `data` is the
/// value of a DNS record, `key` is a map key in a dozen places, and a redactor
/// noisy enough to blank those gets switched off within a day.
pub const SECRET_FIELDS: [&str; 12] = [
    // IAM: the secret half of an API key, returned in full at creation and
    // masked afterwards — but a config import can still carry it.
    "secret_key",
    // Apple silicon servers hand back the sudo password of the machine.
    "sudo_password",
    // Elastic Metal / Dedibox out-of-band console credentials.
    "password",
    // Domains: the private key of a managed certificate.
    "private_key",
    // Domains: the EPP code that authorises a transfer away from the account.
    "epp_code",
    "auth_code",
    // DNS zone TSIG signing key.
    "tsig_key",
    // Messaging & Queuing: a NATS credentials file, whole.
    "credentials",
    // Cockpit: an observability token's own secret.
    "token",
    // Kubernetes: the kubeconfig body, which carries a bearer token.
    "kubeconfig",
    // Secret Manager: the payload of a version, if `--unsafe-values` was used.
    "data_b64",
    // Instances: the ciphertext of the admin password. Encrypted, but there is
    // no reason for a snapshot to carry it.
    "admin_password_encrypted_value",
];

/// What replaces a secret: its length, and nothing else.
///
/// A length is not a secret and it is what a strength check needs, so a
/// redacted snapshot can still be audited. The value never reaches the disk.
pub fn marker(len: usize) -> String {
    format!("<redacted:{len}>")
}

/// Replace every secret in a document, at any depth.
///
/// Returns how many were replaced, which is itself worth recording: it is the
/// measure of what a read-only API key hands over.
pub fn redact(v: &mut Value) -> usize {
    match v {
        Value::Object(map) => {
            let mut n = 0;
            for (k, val) in map.iter_mut() {
                if SECRET_FIELDS.contains(&k.as_str()) {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() {
                            *val = Value::String(marker(s.chars().count()));
                            n += 1;
                            continue;
                        }
                    }
                }
                n += redact(val);
            }
            n
        }
        Value::Array(items) => items.iter_mut().map(redact).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_secret_is_replaced_by_its_length_and_nothing_else() {
        let mut v = json!({"sudo_password": "hunter2!"});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(v["sudo_password"], json!("<redacted:8>"));
    }

    #[test]
    fn secrets_are_found_however_deeply_they_sit() {
        let mut v = json!({"ssl_certificates": [{"private_key": "-----BEGIN"}]});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(
            v["ssl_certificates"][0]["private_key"],
            json!("<redacted:10>")
        );
    }

    #[test]
    fn a_dns_record_value_is_not_a_secret() {
        // `data` is what a DNS record calls its value; a substring rule on it
        // would blank every zone the account holds.
        let mut v = json!({"name": "www", "type": "A", "data": "51.15.0.1"});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["data"], json!("51.15.0.1"));
    }

    #[test]
    fn an_empty_secret_is_left_alone_rather_than_marked() {
        // Marking it would turn "this server has no sudo password" into "this
        // server has one of length zero", which reads as configured.
        let mut v = json!({"sudo_password": ""});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["sudo_password"], json!(""));
    }

    #[test]
    fn everything_else_survives_untouched() {
        let mut v = json!({"name": "arasaka", "is_public": true, "port": 5432});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["name"], json!("arasaka"));
        assert_eq!(v["port"], json!(5432));
    }
}
