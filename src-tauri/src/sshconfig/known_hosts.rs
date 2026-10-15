//! `~/.ssh/known_hosts` entries, including hashed host names
//! (`|1|salt|hash`, the default on Debian/Ubuntu), matched against the hosts
//! being imported.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey};
use sha1::Sha1;

use super::glob_match;

#[derive(Debug, Clone)]
enum HostPattern {
    /// `|1|base64(salt)|base64(HMAC-SHA1(salt, host))`
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
    Plain(String),
    Negated(String),
}

#[derive(Debug, Clone)]
pub struct KnownHostsEntry {
    patterns: Vec<HostPattern>,
    pub key: PublicKey,
}

/// Parse a known_hosts file. `@cert-authority` / `@revoked` lines, key types
/// the parser doesn't know and malformed lines are skipped.
pub fn parse(text: &str) -> Vec<KnownHostsEntry> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<KnownHostsEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let hosts = fields.next()?;
    let key_type = fields.next()?;
    let key_data = fields.next()?;
    let key = PublicKey::from_openssh(&format!("{key_type} {key_data}")).ok()?;
    let patterns: Vec<HostPattern> = hosts.split(',').filter_map(parse_pattern).collect();
    (!patterns.is_empty()).then_some(KnownHostsEntry { patterns, key })
}

fn parse_pattern(pattern: &str) -> Option<HostPattern> {
    if let Some(rest) = pattern.strip_prefix("|1|") {
        let (salt, hash) = rest.split_once('|')?;
        let b64 = base64::engine::general_purpose::STANDARD;
        Some(HostPattern::Hashed {
            salt: b64.decode(salt).ok()?,
            hash: b64.decode(hash).ok()?,
        })
    } else if let Some(negated) = pattern.strip_prefix('!') {
        Some(HostPattern::Negated(negated.to_lowercase()))
    } else if pattern.is_empty() {
        None
    } else {
        Some(HostPattern::Plain(pattern.to_lowercase()))
    }
}

/// How ssh names a host in known_hosts: bare for port 22, `[host]:port` otherwise.
fn host_key_name(host: &str, port: u16) -> String {
    let host = host.to_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

impl KnownHostsEntry {
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let name = host_key_name(host, port);
        let mut matched = false;
        for pattern in &self.patterns {
            match pattern {
                HostPattern::Negated(p) => {
                    if glob_match(p, &name) {
                        return false;
                    }
                }
                HostPattern::Plain(p) => matched |= glob_match(p, &name),
                HostPattern::Hashed { salt, hash } => matched |= hmac_sha1(salt, name.as_bytes()) == *hash,
            }
        }
        matched
    }
}

/// russh's host-key preference (see `Preferred::DEFAULT`); `None` for types it
/// can't negotiate as a host key (DSA, security keys, ...).
fn preference_rank(algorithm: &Algorithm) -> Option<u8> {
    match algorithm {
        Algorithm::Ed25519 => Some(0),
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 } => Some(1),
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 } => Some(2),
        Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 } => Some(3),
        Algorithm::Rsa { .. } => Some(4),
        _ => None,
    }
}

/// The key to pin for `host:port`: among matching entries, the type russh
/// prefers. (The connection then asks the server for that type first; see
/// `ssh::client_config_for`.)
pub fn preferred_key<'a>(entries: &'a [KnownHostsEntry], host: &str, port: u16) -> Option<&'a PublicKey> {
    entries
        .iter()
        .filter(|entry| entry.matches(host, port))
        .filter_map(|entry| preference_rank(&entry.key.algorithm()).map(|rank| (rank, &entry.key)))
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, key)| key)
}

/// Fingerprint and key type exactly as the TOFU check records them.
pub fn pin_for(key: &PublicKey) -> (String, String) {
    (format!("{}", key.fingerprint(HashAlg::Sha256)), key.algorithm().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with `ssh-keygen -H` from plain entries for example.com
    // (ed25519 and RSA) and [example.com]:2222 (ECDSA); fingerprints are
    // `ssh-keygen -lf` output for the same throwaway keys.
    const HASHED: &str = "\
|1|z4E1jpyZgtrkxTyYKlgO5PT7p10=|WNQKDUcILte/4OScieKkJc0BFSE= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMGaPL16Ro3wQhyfr7/wRktUu2x3VOrtX/SB106K/QP8
|1|C96BRWTKqTiWXrezk8L4xfXTrYk=|iGvYpbeqDDkMHOfhlpccIWzpYR8= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKSfHf6L6z7jT6gLllGOYF63bYc5JGfiVFpD9o1qxJD6ZLRjzT2sdgomzveKzmJdSl477t8DoqS6JGiR5/9eXnk=
|1|3CFeQ7BSqmm59q6cArNi+wPJoW4=|tfotaQlHooebp34K9cUJUcOszUU= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCefCF4XRWwCZFi2K6V4j+nl2XWdpduqLFUn9fzgl2l7rwSvyzp34mNBG+/VkpSLv3riGHXESnOCEa4wIsHjTpyGtq7TTCCr5JusXL+umIHeUHQtnhuNiORn4h5oDpzXV6f15vJEU5tQmrUSHUEGgqfwKz/k5dxNjBx+LySgohsNqJJuOmSkIqQgAsl/y8OMELXSEU1FZCR3/B0G+X1gjdi4sgQXDWSf7zulIp5gw8JU8XKpHQ2N+Q8b1SBqEGlnWw1NWfqvLoY+RFKcVheKrUEIbxRnjaAbEuXlS8O7HdhSXtkDvatz20wASObUH+iQdVHZjaH0Px8X91A8OGU4D+1
";

    #[test]
    fn hashed_entries_match_by_host_and_port() {
        let entries = parse(HASHED);
        assert_eq!(entries.len(), 3);

        // Port 22 has ed25519 and RSA: ed25519 is preferred.
        let key = preferred_key(&entries, "EXAMPLE.com", 22).unwrap();
        assert_eq!(
            pin_for(key),
            ("SHA256:r0vYNa2SByOLRLq3lAfzD5mOnqPMC+GUCdDtz6Os2g4".to_string(), "ssh-ed25519".to_string())
        );

        // [example.com]:2222 only has the ECDSA key.
        let key = preferred_key(&entries, "example.com", 2222).unwrap();
        assert_eq!(pin_for(key).0, "SHA256:8hlB8gfiLJNfM6kBPfRn9Sq1AJGwHknTyh7zdyMiyAQ");

        assert!(preferred_key(&entries, "example.org", 22).is_none());
        assert!(preferred_key(&entries, "example.com", 2200).is_none());
    }

    #[test]
    fn plain_wildcard_negated_and_marker_lines() {
        let ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMGaPL16Ro3wQhyfr7/wRktUu2x3VOrtX/SB106K/QP8";
        let text = format!(
            "# comment\n\
             web.example.com,10.0.0.5 {ed}\n\
             *.corp,!secret.corp {ed}\n\
             [10.0.0.9]:2222 {ed}\n\
             @cert-authority *.example.com {ed}\n\
             garbage line\n"
        );
        let entries = parse(&text);
        assert_eq!(entries.len(), 3, "marker and garbage lines skipped");
        assert!(preferred_key(&entries, "10.0.0.5", 22).is_some());
        assert!(preferred_key(&entries, "app.corp", 22).is_some());
        assert!(preferred_key(&entries, "secret.corp", 22).is_none());
        assert!(preferred_key(&entries, "10.0.0.9", 2222).is_some());
        assert!(preferred_key(&entries, "10.0.0.9", 22).is_none());
        // Only the CA line covers this host: not a host key.
        assert!(preferred_key(&entries, "api.example.com", 22).is_none());
    }
}
