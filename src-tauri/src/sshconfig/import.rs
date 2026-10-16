//! Importing hosts from `~/.ssh/config`. Every concrete `Host` alias can
//! become a Termimus SSH host: the key its `IdentityFile` names goes into the
//! Keychain (a Keychain copy of the same key is reused), a single-hop
//! `ProxyJump` becomes its jump host, and host keys `~/.ssh/known_hosts`
//! already trusts are pinned so the first connection doesn't ask about them.
//!
//! A host without a usable key logs in with a password asked at connect time;
//! an encrypted key saved without its passphrase asks for it the same way.

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use chrono::Utc;
use russh::keys::decode_secret_key;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::known_hosts::{self, KnownHostsEntry};
use super::{expand_tilde, parse_jump, read_limited, ResolvedHost, SshConfig};
use crate::db::models::{Credential, Folder, Host, KeychainItem, KnownHost};
use crate::db::Database;
use crate::sshkey::{self, KeyDetails};
use crate::vault::VaultManager;

/// Tag on every imported host.
const IMPORT_TAG: &str = "ssh-config";
/// Keys ssh tries when a host names no `IdentityFile`, in its order (its
/// security-key and DSA defaults can't be used here).
const DEFAULT_IDENTITIES: [&str; 3] = ["id_rsa", "id_ecdsa", "id_ed25519"];
const MAX_KEY_BYTES: u64 = 64 * 1024;
const MAX_KNOWN_HOSTS_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub config_path: String,
    pub hosts: Vec<HostPreview>,
    /// Every key the hosts and the jump hosts created for them would use.
    pub keys: Vec<KeyPreview>,
    /// known_hosts files found in ~/.ssh.
    pub known_hosts_files: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostPreview {
    pub alias: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    /// The key it logs in with (a `KeyPreview::path`). Without one, the
    /// password is asked at login.
    pub identity_file: Option<String>,
    /// The config names no key; this is the default key ssh tries first.
    pub default_identity: bool,
    /// `ProxyJump` as written in the config.
    pub proxy_jump: Option<String>,
    /// The key of a jump host the import would create.
    pub jump_identity_file: Option<String>,
    /// Label of the Termimus host with the same address, port and user.
    pub existing_host: Option<String>,
    /// An earlier alias for the same address, port and user.
    pub same_as: Option<String>,
    /// known_hosts has a host key for it.
    pub known_host_key: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Ok,
    /// Needs its passphrase: saved with the import, or asked at login.
    Encrypted,
    Missing,
    Unusable,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPreview {
    pub path: String,
    pub display_path: String,
    pub status: KeyStatus,
    /// "ED25519", "RSA" or "ECDSA"; empty when the key doesn't show it.
    pub key_type: String,
    pub fingerprint: String,
    pub detail: Option<String>,
    /// The Keychain key with the same fingerprint, used instead of a copy.
    pub keychain_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub config_path: Option<String>,
    pub aliases: Vec<String>,
    /// Folder for the new hosts, created unless one by that name exists.
    pub folder_name: Option<String>,
    pub trust_known_hosts: bool,
    /// Passphrases to save with encrypted keys, by `KeyPreview::path`.
    #[serde(default)]
    pub key_passphrases: HashMap<String, String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub hosts_added: usize,
    pub jump_hosts_added: usize,
    pub keys_added: usize,
    pub keys_reused: usize,
    pub host_keys_trusted: usize,
    pub warnings: Vec<String>,
}

/// The config and what sits next to it, read once per preview or import.
struct Source {
    home: PathBuf,
    config_path: PathBuf,
    config: SshConfig,
    /// User for hosts the config names none for (ssh uses the local user).
    local_user: String,
    known_hosts: Vec<KnownHostsEntry>,
    known_hosts_files: Vec<PathBuf>,
    warnings: Vec<String>,
}

/// One Termimus host for a config entry or a jump host.
#[derive(Debug, Clone)]
struct Plan {
    label: String,
    address: String,
    port: u16,
    username: String,
    identity: Option<PathBuf>,
    default_identity: bool,
    proxy_jump: Option<String>,
    notes: Vec<String>,
}

impl Plan {
    fn same_host(&self, other: &Plan) -> bool {
        self.address.eq_ignore_ascii_case(&other.address) && self.port == other.port && self.username == other.username
    }

    fn matches(&self, host: &Host) -> bool {
        host.protocol == "ssh"
            && host.address.eq_ignore_ascii_case(&self.address)
            && host.port == self.port
            && host.username == self.username
    }
}

impl Source {
    fn load(home: &Path, config_path: Option<&str>) -> Result<Self, String> {
        let config_path = match config_path.map(str::trim).filter(|path| !path.is_empty()) {
            Some(path) => home.join(expand_tilde(path, home)),
            None => home.join(".ssh").join("config"),
        };
        let config = SshConfig::load(&config_path, home).map_err(|e| match e.kind() {
            ErrorKind::NotFound => format!("No SSH config at {}", config_path.display()),
            _ => format!("Could not read {}: {e}", config_path.display()),
        })?;
        let mut warnings = config.warnings.clone();
        let mut known_hosts = Vec::new();
        let mut known_hosts_files = Vec::new();
        // ssh's default UserKnownHostsFile.
        for name in ["known_hosts", "known_hosts2"] {
            let path = home.join(".ssh").join(name);
            if !path.is_file() {
                continue;
            }
            match read_limited(&path, MAX_KNOWN_HOSTS_BYTES) {
                Ok(text) => {
                    known_hosts.extend(known_hosts::parse(&text));
                    known_hosts_files.push(path);
                }
                Err(e) => warnings.push(format!("Could not read {}: {e}", path.display())),
            }
        }
        Ok(Source {
            home: home.to_path_buf(),
            config_path,
            config,
            local_user: local_user(home),
            known_hosts,
            known_hosts_files,
            warnings,
        })
    }

    /// `~/...` for paths in the home directory.
    fn display(&self, path: &Path) -> String {
        match path.strip_prefix(&self.home) {
            Ok(rest) if self.home != Path::new("/") => format!("~/{}", rest.display()),
            _ => path.display().to_string(),
        }
    }

    fn plan(&self, resolved: ResolvedHost) -> Plan {
        let mut notes = Vec::new();
        if resolved.proxy_command {
            notes.push("ProxyCommand isn't supported; imported as a direct connection.".to_string());
        }
        let (identity, default_identity) = match resolved.identity_file {
            Some(path) => (Some(path), false),
            None => {
                let default = DEFAULT_IDENTITIES
                    .iter()
                    .map(|name| self.home.join(".ssh").join(name))
                    .find(|path| path.is_file());
                let found = default.is_some();
                (default, found)
            }
        };
        Plan {
            label: resolved.alias,
            address: resolved.hostname,
            port: resolved.port,
            username: resolved.user.unwrap_or_else(|| self.local_user.clone()),
            identity,
            default_identity,
            proxy_jump: resolved.proxy_jump,
            notes,
        }
    }

    /// The host for `alias` and the jump host it goes through, if any.
    fn plan_alias(&self, alias: &str) -> (Plan, Option<Plan>) {
        let mut plan = self.plan(self.config.resolve(alias, &self.home));
        let Some(spec) = plan.proxy_jump.clone() else {
            return (plan, None);
        };
        let hop = match parse_jump(&spec) {
            Ok(hop) => hop,
            Err(e) => {
                plan.notes.push(format!("ProxyJump {spec}: {e}; imported without a jump host."));
                return (plan, None);
            }
        };
        // Like ssh, look the jump host up in the config by the name given.
        let hop_name = hop.host.clone();
        let mut resolved = self.config.resolve(&hop.host, &self.home);
        if let Some(port) = hop.port {
            resolved.port = port;
        }
        if hop.user.is_some() {
            resolved.user = hop.user;
        }
        let jump = self.plan(resolved);
        // A `Host *` ProxyJump also covers the jump host itself.
        if jump.same_host(&plan) {
            return (plan, None);
        }
        let chained = jump
            .proxy_jump
            .as_deref()
            .is_some_and(|next| parse_jump(next).map_or(true, |next| !next.host.eq_ignore_ascii_case(&hop_name)));
        if chained {
            plan.notes.push(format!(
                "Jump host {} goes through another jump host, which isn't supported; only the first hop is set.",
                jump.label
            ));
        }
        (plan, Some(jump))
    }

    fn key_preview(&self, path: &Path, keychain: &[KeychainItem]) -> KeyPreview {
        let (status, details, detail) = match inspect_key_file(path) {
            Inspected::Ready(details) => (KeyStatus::Ok, Some(details), None),
            Inspected::Locked(details) => (KeyStatus::Encrypted, details, None),
            problem @ Inspected::Missing => (KeyStatus::Missing, None, Some(problem.reason())),
            problem @ Inspected::Unusable(_) => (KeyStatus::Unusable, None, Some(problem.reason())),
        };
        let (key_type, fingerprint) = details.map(|d| (d.algorithm, d.fingerprint)).unwrap_or_default();
        let keychain_name = keychain
            .iter()
            .find(|item| !fingerprint.is_empty() && item.kind == "private_key" && item.fingerprint == fingerprint)
            .map(|item| item.name.clone());
        KeyPreview {
            path: path_string(path),
            display_path: self.display(path),
            status,
            key_type,
            fingerprint,
            detail,
            keychain_name,
        }
    }
}

fn local_user(home: &Path) -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|user| !user.is_empty())
        .or_else(|| home.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "root".to_string())
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

enum Inspected {
    Ready(KeyDetails),
    /// Encrypted; the details if the format shows them without the passphrase.
    Locked(Option<KeyDetails>),
    Missing,
    Unusable(String),
}

impl Inspected {
    fn reason(&self) -> String {
        match self {
            Inspected::Missing => "File not found".to_string(),
            Inspected::Unusable(reason) => reason.clone(),
            Inspected::Ready(_) | Inspected::Locked(_) => String::new(),
        }
    }
}

fn read_key(path: &Path) -> Result<String, Inspected> {
    read_limited(path, MAX_KEY_BYTES).map_err(|e| match e.kind() {
        ErrorKind::NotFound => Inspected::Missing,
        _ => Inspected::Unusable(format!("Can't read it: {e}")),
    })
}

fn inspect_key_file(path: &Path) -> Inspected {
    match read_key(path) {
        Ok(pem) => inspect_key_text(&pem),
        Err(problem) => problem,
    }
}

fn inspect_key_text(pem: &str) -> Inspected {
    let pem = pem.trim();
    if sshkey::is_public_key_text(pem) {
        return Inspected::Unusable("It's a public key; the private key is needed".to_string());
    }
    let inspected = match decode_secret_key(pem, None) {
        Ok(key) => match sshkey::describe_public_key(key.public_key(), false) {
            Ok(details) => Inspected::Ready(details),
            Err(e) => Inspected::Unusable(e),
        },
        Err(e) if sshkey::is_missing_passphrase(pem, &e) => Inspected::Locked(sshkey::inspect_encrypted_key(pem)),
        Err(e) => Inspected::Unusable(format!("Not a private key Termimus can read ({e})")),
    };
    // Security-key (FIDO) and DSA keys can't log in here.
    match &inspected {
        Inspected::Ready(details) | Inspected::Locked(Some(details))
            if !matches!(details.algorithm.as_str(), "ED25519" | "RSA" | "ECDSA") =>
        {
            Inspected::Unusable(format!("{} keys aren't supported", details.algorithm))
        }
        _ => inspected,
    }
}

enum LoadedKey {
    Usable { pem: String, details: KeyDetails },
    Unusable(String),
}

/// Read a key to save. A passphrase given for it must unlock it: a wrong one
/// is an error, so nothing is imported with it.
fn load_key(path: &Path, passphrase: Option<&str>) -> Result<LoadedKey, String> {
    let pem = match read_key(path) {
        Ok(pem) => pem,
        Err(problem) => return Ok(LoadedKey::Unusable(problem.reason())),
    };
    let details = match inspect_key_text(&pem) {
        Inspected::Ready(details) => details,
        Inspected::Locked(details) => match passphrase {
            Some(passphrase) => {
                let key = decode_secret_key(pem.trim(), Some(passphrase))
                    .map_err(|_| format!("Wrong passphrase for {}", path.display()))?;
                sshkey::describe_public_key(key.public_key(), false)?
            }
            // Saved locked: the passphrase is asked at login.
            None => details.unwrap_or(KeyDetails {
                algorithm: String::new(),
                public_key: String::new(),
                fingerprint: String::new(),
                is_public_key_only: false,
            }),
        },
        problem => return Ok(LoadedKey::Unusable(problem.reason())),
    };
    Ok(LoadedKey::Usable { pem, details })
}

/// Keychain name for a key file: its file name, numbered when taken.
fn unique_name(path: &Path, taken: &mut HashSet<String>) -> String {
    let base = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "imported key".to_string());
    let mut name = base.clone();
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{base} ({n})");
        n += 1;
    }
    taken.insert(name.clone());
    name
}

fn seal_key(
    vault: &VaultManager,
    pem: &str,
    passphrase: Option<&str>,
    details: KeyDetails,
    name: String,
    now: &str,
) -> Result<Credential, String> {
    let (ciphertext, nonce) = vault.encrypt(pem.as_bytes())?;
    let (passphrase_ciphertext, passphrase_nonce) = match passphrase {
        Some(passphrase) => {
            let (ciphertext, nonce) = vault.encrypt(passphrase.as_bytes())?;
            (Some(ciphertext), Some(nonce))
        }
        None => (None, None),
    };
    Ok(Credential {
        id: Uuid::new_v4().to_string(),
        kind: "private_key".to_string(),
        ciphertext,
        nonce,
        passphrase_ciphertext,
        passphrase_nonce,
        name,
        key_type: details.algorithm,
        public_key: details.public_key,
        fingerprint: details.fingerprint,
        username: None,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    })
}

fn folder_for(db: &Database, name: &str, now: &str) -> Result<String, String> {
    let folders = db.list_folders().map_err(|e| e.to_string())?;
    if let Some(folder) = folders.iter().find(|f| f.parent_id.is_none() && f.name == name) {
        return Ok(folder.id.clone());
    }
    let folder = Folder {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        parent_id: None,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    };
    db.save_folder(&folder).map_err(|e| e.to_string())?;
    Ok(folder.id)
}

pub fn preview(db: &Database, home: &Path, config_path: Option<&str>) -> Result<ImportPreview, String> {
    let source = Source::load(home, config_path)?;
    let existing = db.list_hosts().map_err(|e| e.to_string())?;
    let keychain = db.list_keychain_items().map_err(|e| e.to_string())?;

    let mut hosts = Vec::new();
    let mut plans: Vec<Plan> = Vec::new();
    let mut key_paths: Vec<PathBuf> = Vec::new();
    for alias in source.config.aliases() {
        let (plan, jump) = source.plan_alias(&alias);
        // A jump host already in Termimus keeps its own credentials.
        let jump_identity = jump
            .filter(|jump| !existing.iter().any(|host| jump.matches(host)))
            .and_then(|jump| jump.identity);
        for path in [plan.identity.as_ref(), jump_identity.as_ref()].into_iter().flatten() {
            if !key_paths.contains(path) {
                key_paths.push(path.clone());
            }
        }
        hosts.push(HostPreview {
            alias,
            address: plan.address.clone(),
            port: plan.port,
            username: plan.username.clone(),
            identity_file: plan.identity.as_deref().map(path_string),
            default_identity: plan.default_identity,
            proxy_jump: plan.proxy_jump.clone(),
            jump_identity_file: jump_identity.as_deref().map(path_string),
            existing_host: existing.iter().find(|host| plan.matches(host)).map(|host| host.label.clone()),
            same_as: plans.iter().find(|earlier| earlier.same_host(&plan)).map(|earlier| earlier.label.clone()),
            known_host_key: known_hosts::preferred_key(&source.known_hosts, &plan.address, plan.port).is_some(),
            notes: plan.notes.clone(),
        });
        plans.push(plan);
    }
    let keys = key_paths.iter().map(|path| source.key_preview(path, &keychain)).collect();
    Ok(ImportPreview {
        config_path: source.display(&source.config_path),
        hosts,
        keys,
        known_hosts_files: source.known_hosts_files.iter().map(|path| source.display(path)).collect(),
        warnings: source.warnings,
    })
}

struct NewHost {
    id: String,
    plan: Plan,
    jump_host_id: Option<String>,
}

impl NewHost {
    fn new(plan: Plan) -> Self {
        NewHost {
            id: Uuid::new_v4().to_string(),
            plan,
            jump_host_id: None,
        }
    }

    fn into_host(self, folder_id: Option<String>, credential_id: Option<String>, now: &str) -> Host {
        Host {
            id: self.id,
            folder_id,
            label: self.plan.label,
            address: self.plan.address,
            port: self.plan.port,
            username: self.plan.username,
            // Without a usable key the password is asked at login.
            auth_method: if credential_id.is_some() { "private_key" } else { "password" }.to_string(),
            credential_id,
            tags: vec![IMPORT_TAG.to_string()],
            last_connected_at: None,
            os_icon: None,
            jump_host_id: self.jump_host_id,
            protocol: "ssh".to_string(),
            protocol_options: None,
            created_at: now.to_string(),
            updated_at: now.to_string(),
        }
    }
}

pub fn import(db: &Database, vault: &VaultManager, home: &Path, request: &ImportRequest) -> Result<ImportResult, String> {
    if !vault.is_unlocked() {
        return Err("Unlock the vault to import hosts".to_string());
    }
    let source = Source::load(home, request.config_path.as_deref())?;
    let existing = db.list_hosts().map_err(|e| e.to_string())?;
    let keychain = db.list_keychain_items().map_err(|e| e.to_string())?;
    let aliases = source.config.aliases();
    let now = Utc::now().to_rfc3339();
    let mut result = ImportResult::default();

    // Hosts already in Termimus are left alone.
    let mut new_hosts: Vec<NewHost> = Vec::new();
    let mut jumps: Vec<(usize, Plan)> = Vec::new();
    for alias in &request.aliases {
        if !aliases.contains(alias) {
            result.warnings.push(format!("{alias} is no longer in the config"));
            continue;
        }
        let (plan, jump) = source.plan_alias(alias);
        if existing.iter().any(|host| plan.matches(host)) {
            continue;
        }
        if let Some(jump) = jump {
            jumps.push((new_hosts.len(), jump));
        }
        new_hosts.push(NewHost::new(plan));
    }
    result.hosts_added = new_hosts.len();

    // A jump host is one of the imported hosts, a host already in Termimus,
    // or else a new host of its own.
    for (index, jump) in jumps {
        let found = new_hosts
            .iter()
            .find(|host| host.plan.same_host(&jump))
            .map(|host| host.id.clone())
            .or_else(|| existing.iter().find(|host| jump.matches(host)).map(|host| host.id.clone()));
        let jump_id = found.unwrap_or_else(|| {
            let host = NewHost::new(jump);
            let id = host.id.clone();
            new_hosts.push(host);
            id
        });
        new_hosts[index].jump_host_id = Some(jump_id);
    }
    result.jump_hosts_added = new_hosts.len() - result.hosts_added;

    // Every key is read and checked before anything is saved, so a wrong
    // passphrase stops the import as a whole.
    let mut names: HashSet<String> = keychain.iter().map(|item| item.name.clone()).collect();
    let mut credentials: Vec<Credential> = Vec::new();
    let mut key_ids: HashMap<PathBuf, Option<String>> = HashMap::new();
    for host in &new_hosts {
        let Some(path) = &host.plan.identity else { continue };
        if key_ids.contains_key(path) {
            continue;
        }
        let passphrase = request
            .key_passphrases
            .get(&path_string(path))
            .map(String::as_str)
            .filter(|passphrase| !passphrase.is_empty());
        let id = match load_key(path, passphrase)? {
            LoadedKey::Unusable(reason) => {
                result.warnings.push(format!(
                    "{}: {reason}. Hosts using it ask for a password at login.",
                    source.display(path)
                ));
                None
            }
            LoadedKey::Usable { pem, details } => {
                let fingerprint = details.fingerprint.as_str();
                let same_key = keychain
                    .iter()
                    .find(|item| !fingerprint.is_empty() && item.kind == "private_key" && item.fingerprint == fingerprint)
                    .map(|item| item.id.clone())
                    .or_else(|| {
                        credentials
                            .iter()
                            .find(|c| !fingerprint.is_empty() && c.fingerprint == fingerprint)
                            .map(|c| c.id.clone())
                    });
                match same_key {
                    Some(id) => {
                        result.keys_reused += 1;
                        Some(id)
                    }
                    None => {
                        let name = unique_name(path, &mut names);
                        let credential = seal_key(vault, &pem, passphrase, details, name, &now)?;
                        result.keys_added += 1;
                        let id = credential.id.clone();
                        credentials.push(credential);
                        Some(id)
                    }
                }
            }
        };
        key_ids.insert(path.clone(), id);
    }

    // Pins never replace a host key Termimus already trusts.
    let mut pins: Vec<KnownHost> = Vec::new();
    if request.trust_known_hosts {
        for host in &new_hosts {
            let (address, port) = (host.plan.address.as_str(), host.plan.port);
            if pins.iter().any(|pin| pin.address == address && pin.port == port) {
                continue;
            }
            let Some(key) = known_hosts::preferred_key(&source.known_hosts, address, port) else {
                continue;
            };
            let (fingerprint, key_type) = known_hosts::pin_for(key);
            match db.get_known_host(address, port).map_err(|e| e.to_string())? {
                Some(trusted) if trusted.fingerprint == fingerprint => {}
                Some(_) => result.warnings.push(format!(
                    "{address}:{port}: known_hosts has a different host key than the one Termimus trusts; kept Termimus's"
                )),
                None => pins.push(KnownHost {
                    address: address.to_string(),
                    port,
                    key_type,
                    fingerprint,
                    first_seen_at: now.clone(),
                    last_seen_at: now.clone(),
                }),
            }
        }
    }

    let folder_id = match request.folder_name.as_deref().map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) if !new_hosts.is_empty() => Some(folder_for(db, name, &now)?),
        _ => None,
    };
    for credential in &credentials {
        db.save_credential(credential).map_err(|e| e.to_string())?;
    }
    for host in new_hosts {
        let credential_id = host.plan.identity.as_ref().and_then(|path| key_ids.get(path).cloned().flatten());
        db.save_host(&host.into_host(folder_id.clone(), credential_id, &now))
            .map_err(|e| e.to_string())?;
    }
    for pin in &pins {
        db.save_known_host(pin).map_err(|e| e.to_string())?;
    }
    result.host_keys_trusted = pins.len();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::{Algorithm, Cipher, HashAlg, Kdf, LineEnding, PrivateKey};

    const CONFIG: &str = "\
Host *
    ServerAliveInterval 30

Host web
    HostName web.example.com
    User deploy
    IdentityFile ~/.ssh/id_work

Host db
    HostName 10.0.0.20
    User postgres
    Port 2222
    IdentityFile ~/.ssh/id_locked
    ProxyJump bastion

Host bastion
    HostName 203.0.113.10
    User ops
    IdentityFile ~/.ssh/id_work

Host legacy
    HostName legacy.example.com
    User admin
    ProxyCommand nc -X 5 -x proxy:1080 %h %p

Host inner
    HostName 10.0.0.30
    User admin
    ProxyJump jump@198.51.100.7:2200

Host multi
    HostName 10.0.0.40
    User admin
    ProxyJump a,b

Host web-again
    HostName web.example.com
    User deploy
    IdentityFile ~/.ssh/id_ed25519

Host gone
    HostName 10.0.0.50
    User admin
    IdentityFile ~/.ssh/id_missing
";

    struct Fixture {
        home: PathBuf,
        db: Database,
        vault: VaultManager,
        work: PrivateKey,
        locked: PrivateKey,
        db_host_key: PrivateKey,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    fn random_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap()
    }

    fn fingerprint(key: &PrivateKey) -> String {
        key.public_key().fingerprint(HashAlg::Sha256).to_string()
    }

    fn fixture() -> Fixture {
        let home = std::env::temp_dir().join(format!("termimus-import-{}", Uuid::new_v4()));
        let ssh = home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("config"), CONFIG).unwrap();

        let work = random_key();
        let work_pem = work.to_openssh(LineEnding::LF).unwrap().to_string();
        std::fs::write(ssh.join("id_work"), &work_pem).unwrap();
        // The same key again under the default name.
        std::fs::write(ssh.join("id_ed25519"), &work_pem).unwrap();
        let locked = random_key();
        // One bcrypt round keeps the debug-build test fast.
        let kdf = Kdf::Bcrypt { salt: vec![3; 16], rounds: 1 };
        let encrypted = locked.encrypt_with(Cipher::Aes256Ctr, kdf, 11, "s3cret").unwrap();
        std::fs::write(ssh.join("id_locked"), encrypted.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();

        let db_host_key = random_key();
        let web_host_key = random_key();
        std::fs::write(
            ssh.join("known_hosts"),
            format!(
                "[10.0.0.20]:2222 {}\nweb.example.com {}\n",
                db_host_key.public_key().to_openssh().unwrap(),
                web_host_key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        let vault = VaultManager::new();
        vault.set_key([9; 32]);
        Fixture { home, db: Database::in_memory().unwrap(), vault, work, locked, db_host_key }
    }

    fn request(aliases: &[&str]) -> ImportRequest {
        ImportRequest {
            config_path: None,
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            folder_name: Some("SSH Config".to_string()),
            trust_known_hosts: true,
            key_passphrases: HashMap::new(),
        }
    }

    fn key_path(f: &Fixture, name: &str) -> String {
        path_string(&f.home.join(".ssh").join(name))
    }

    #[test]
    fn preview_lists_hosts_keys_and_what_cannot_be_imported() {
        let f = fixture();
        let preview = preview(&f.db, &f.home, None).unwrap();
        assert_eq!(preview.config_path, "~/.ssh/config");
        assert_eq!(preview.known_hosts_files, vec!["~/.ssh/known_hosts"]);
        let host = |alias: &str| preview.hosts.iter().find(|h| h.alias == alias).unwrap();
        let aliases: Vec<&str> = preview.hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["web", "db", "bastion", "legacy", "inner", "multi", "web-again", "gone"]);

        let db = host("db");
        assert_eq!((db.address.as_str(), db.port, db.username.as_str()), ("10.0.0.20", 2222, "postgres"));
        assert_eq!(db.proxy_jump.as_deref(), Some("bastion"));
        assert_eq!(db.jump_identity_file, Some(key_path(&f, "id_work")));
        assert!(db.known_host_key && host("web").known_host_key && !host("bastion").known_host_key);
        assert!(db.notes.is_empty());
        assert!(host("legacy").notes[0].starts_with("ProxyCommand"));
        assert!(host("multi").notes[0].contains("multi-hop"));
        assert_eq!(host("web-again").same_as.as_deref(), Some("web"));

        let key = |name: &str| preview.keys.iter().find(|k| k.path == key_path(&f, name)).unwrap();
        assert_eq!(key("id_work").status, KeyStatus::Ok);
        assert_eq!(key("id_work").key_type, "ED25519");
        assert_eq!(key("id_work").fingerprint, fingerprint(&f.work));
        assert_eq!(key("id_work").display_path, "~/.ssh/id_work");
        // The public half of an encrypted OpenSSH key is readable.
        assert_eq!(key("id_locked").status, KeyStatus::Encrypted);
        assert_eq!(key("id_locked").fingerprint, fingerprint(&f.locked));
        assert_eq!(key("id_missing").status, KeyStatus::Missing);
        // inner's literal jump host has no IdentityFile: ssh's default key.
        assert_eq!(key("id_ed25519").status, KeyStatus::Ok);
    }

    #[test]
    fn import_creates_hosts_jump_hosts_keys_and_pins() {
        let f = fixture();

        // A wrong passphrase stops the import before anything is saved.
        let mut wrong = request(&["web", "db"]);
        wrong.key_passphrases.insert(key_path(&f, "id_locked"), "nope".to_string());
        let err = import(&f.db, &f.vault, &f.home, &wrong).unwrap_err();
        assert!(err.starts_with("Wrong passphrase"), "{err}");
        assert!(f.db.list_hosts().unwrap().is_empty());
        assert!(f.db.list_keychain_items().unwrap().is_empty());

        let mut req = request(&["web", "db", "inner", "multi", "gone"]);
        req.key_passphrases.insert(key_path(&f, "id_locked"), "s3cret".to_string());
        let result = import(&f.db, &f.vault, &f.home, &req).unwrap();
        assert_eq!(result.hosts_added, 5);
        // bastion (an alias that wasn't picked) and inner's literal jump host.
        assert_eq!(result.jump_hosts_added, 2);
        // id_work and id_locked; id_ed25519 is id_work again.
        assert_eq!((result.keys_added, result.keys_reused), (2, 1));
        assert_eq!(result.host_keys_trusted, 2);
        assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
        assert!(result.warnings[0].starts_with("~/.ssh/id_missing: File not found"));

        let hosts = f.db.list_hosts().unwrap();
        let host = |label: &str| hosts.iter().find(|h| h.label == label).unwrap();
        let folder = f.db.list_folders().unwrap().into_iter().find(|f| f.name == "SSH Config").unwrap();
        assert!(hosts.iter().all(|h| h.folder_id.as_deref() == Some(folder.id.as_str()) && h.tags == ["ssh-config"]));

        let db = host("db");
        assert_eq!(db.jump_host_id.as_deref(), Some(host("bastion").id.as_str()));
        assert_eq!(db.auth_method, "private_key");
        let locked = f.db.get_credential(db.credential_id.as_deref().unwrap()).unwrap().unwrap();
        assert_eq!(locked.name, "id_locked");
        assert_eq!(locked.fingerprint, fingerprint(&f.locked));
        let saved_passphrase = f
            .vault
            .decrypt(&locked.passphrase_ciphertext.unwrap(), &locked.passphrase_nonce.unwrap())
            .unwrap();
        assert_eq!(saved_passphrase, b"s3cret");

        let hop = host("198.51.100.7");
        assert_eq!((hop.port, hop.username.as_str()), (2200, "jump"));
        assert_eq!(host("inner").jump_host_id.as_deref(), Some(hop.id.as_str()));
        // Every id_work / id_ed25519 user shares one Keychain key.
        assert_eq!(host("web").credential_id, host("bastion").credential_id);
        assert_eq!(host("web").credential_id, host("inner").credential_id);
        assert_eq!(host("multi").jump_host_id, None);
        assert_eq!((host("gone").auth_method.as_str(), host("gone").credential_id.as_deref()), ("password", None));

        let pin = f.db.get_known_host("10.0.0.20", 2222).unwrap().unwrap();
        assert_eq!(pin.fingerprint, fingerprint(&f.db_host_key));
        assert_eq!(pin.key_type, "ssh-ed25519");

        // Importing again adds nothing; the preview now shows them as existing.
        let again = import(&f.db, &f.vault, &f.home, &req).unwrap();
        assert_eq!((again.hosts_added, again.jump_hosts_added, again.keys_added), (0, 0, 0));
        assert_eq!(f.db.list_hosts().unwrap().len(), 7);
        let preview = preview(&f.db, &f.home, None).unwrap();
        assert_eq!(preview.hosts[0].existing_host.as_deref(), Some("web"));
        let work = preview.keys.iter().find(|k| k.path == key_path(&f, "id_work")).unwrap();
        assert_eq!(work.keychain_name.as_deref(), Some("id_work"));
    }

    #[test]
    fn trusted_host_key_is_never_replaced() {
        let f = fixture();
        let other = random_key();
        let pinned = KnownHost {
            address: "web.example.com".to_string(),
            port: 22,
            key_type: "ssh-ed25519".to_string(),
            fingerprint: fingerprint(&other),
            first_seen_at: "2026-01-01T00:00:00Z".to_string(),
            last_seen_at: "2026-01-01T00:00:00Z".to_string(),
        };
        f.db.save_known_host(&pinned).unwrap();
        let result = import(&f.db, &f.vault, &f.home, &request(&["web"])).unwrap();
        assert_eq!(result.host_keys_trusted, 0);
        assert!(result.warnings[0].contains("different host key"));
        assert_eq!(f.db.get_known_host("web.example.com", 22).unwrap().unwrap().fingerprint, fingerprint(&other));
    }

    // ── End-to-end against a real sshd ─────────────────────────────────────
    //
    // SSH_TEST_ADDR=127.0.0.1:2222 SSH_TEST_USER=root SSH_TEST_KEY=/path/to/key \
    // SSH_TEST_KNOWN_HOSTS=/path/to/known_hosts cargo test -- --ignored import_end_to_end
    //
    // known_hosts must hold the server's key for `[127.0.0.1]:port` and
    // `[localhost]:port`. With a type the server wouldn't offer first (e.g.
    // only its ECDSA key) it also checks that the pinned type is negotiated.

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn import_end_to_end() {
        use crate::ssh::{connect_authenticated, JumpHostConfig, SshAuth};
        use std::sync::Arc;

        let addr = std::env::var("SSH_TEST_ADDR").expect("SSH_TEST_ADDR");
        let (address, port) = addr.rsplit_once(':').expect("host:port");
        let user = std::env::var("SSH_TEST_USER").expect("SSH_TEST_USER");
        let key = std::fs::read_to_string(std::env::var("SSH_TEST_KEY").expect("SSH_TEST_KEY")).unwrap();
        let known_hosts = std::env::var("SSH_TEST_KNOWN_HOSTS").expect("SSH_TEST_KNOWN_HOSTS");

        let home = std::env::temp_dir().join(format!("termimus-import-e2e-{}", Uuid::new_v4()));
        let ssh = home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("e2e_key"), key).unwrap();
        std::fs::copy(known_hosts, ssh.join("known_hosts")).unwrap();
        std::fs::write(
            ssh.join("config"),
            format!(
                "Host bastion\n  HostName {address}\n  Port {port}\n  User {user}\n  IdentityFile ~/.ssh/e2e_key\n\n\
                 Host inside\n  HostName localhost\n  Port {port}\n  User {user}\n  IdentityFile ~/.ssh/e2e_key\n  ProxyJump bastion\n"
            ),
        )
        .unwrap();

        let db = Arc::new(Database::in_memory().unwrap());
        let vault = VaultManager::new();
        vault.set_key([5; 32]);
        // Only `inside` is picked: `bastion` comes along as its jump host.
        let result = import(&db, &vault, &home, &request(&["inside"])).unwrap();
        assert_eq!(
            (result.hosts_added, result.jump_hosts_added, result.keys_added, result.host_keys_trusted),
            (1, 1, 1, 2),
            "{:?}",
            result.warnings
        );
        let hosts = db.list_hosts().unwrap();
        let inside = hosts.iter().find(|h| h.label == "inside").unwrap();
        let bastion = hosts.iter().find(|h| h.label == "bastion").unwrap();
        assert_eq!(inside.jump_host_id.as_deref(), Some(bastion.id.as_str()));
        let auth_for = |host: &Host| {
            let credential = db.get_credential(host.credential_id.as_deref().unwrap()).unwrap().unwrap();
            let pem = String::from_utf8(vault.decrypt(&credential.ciphertext, &credential.nonce).unwrap()).unwrap();
            SshAuth::PrivateKey { pem, passphrase: None }
        };
        let pin = db.get_known_host(&bastion.address, bastion.port).unwrap().unwrap();
        println!("pinned from known_hosts: {} {}", pin.key_type, pin.fingerprint);

        // The imported pins verify both hops.
        let (direct, _) = connect_authenticated(db.clone(), &bastion.address, bastion.port, &bastion.username, &auth_for(bastion), None)
            .await
            .expect("direct login");
        drop(direct);
        let jump = JumpHostConfig {
            address: bastion.address.clone(),
            port: bastion.port,
            username: bastion.username.clone(),
            auth: auth_for(bastion),
        };
        let (_session, _jump) =
            connect_authenticated(db.clone(), &inside.address, inside.port, &inside.username, &auth_for(inside), Some(&jump))
                .await
                .expect("login through the jump host");

        // A pinned key the server doesn't have is refused.
        let mut wrong = pin.clone();
        wrong.fingerprint = format!("SHA256:{}", "A".repeat(43));
        db.save_known_host(&wrong).unwrap();
        let err = connect_authenticated(db.clone(), &bastion.address, bastion.port, &bastion.username, &auth_for(bastion), None)
            .await
            .err()
            .expect("a changed host key must be refused");
        println!("refused: {err}");
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn encrypted_key_without_passphrase_is_saved_locked() {
        let f = fixture();
        let result = import(&f.db, &f.vault, &f.home, &request(&["db"])).unwrap();
        assert_eq!(result.keys_added, 2, "id_locked and bastion's id_work");
        let db = f.db.list_hosts().unwrap().into_iter().find(|h| h.label == "db").unwrap();
        let locked = f.db.get_credential(db.credential_id.as_deref().unwrap()).unwrap().unwrap();
        assert!(locked.passphrase_ciphertext.is_none());
        assert_eq!(locked.fingerprint, fingerprint(&f.locked));
    }
}
