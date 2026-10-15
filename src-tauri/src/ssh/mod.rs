use russh::client::{self, Handle, Handler};
use russh::keys::ssh_key::HashAlg;
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg};
use russh::Disconnect;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::db::models::KnownHost;
use crate::db::Database;
use auth_prompt::{AuthPromptRequest, AuthPrompter, PromptField, UiPrompter};
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::MethodKind;
use zeroize::Zeroizing;

pub mod auth_prompt;
#[cfg(test)]
mod auth_tests;
#[cfg(test)]
pub(crate) mod e2e_tests;

/// Keyboard-interactive rounds allowed per login: PAM stacks ask a few, a
/// server that keeps asking must not hang the connect forever.
const MAX_KBD_INTERACTIVE_ROUNDS: usize = 10;

/// Tries for a password or key passphrase typed at login (ssh's
/// NumberOfPasswordPrompts).
const SECRET_ATTEMPTS: usize = 3;

/// Configures a `TcpStream` with low-latency (`TCP_NODELAY`) and socket-level
/// TCP keepalive (15s idle probe, 5s retry interval) to prevent stateful NAT routers,
/// middleboxes, and cloud VPC firewalls from terminating idle connections.
pub fn configure_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// Creates a standard `russh::client::Config` with SSH-level keepalive enabled.
/// Sends `keepalive@openssh.com` probes every 15 seconds to ensure sessions
/// (interactive shells, long-running monitoring like btop/htop, SFTP, tunnels)
/// never get dropped by remote servers or NAT translation timeouts.
fn base_client_config() -> client::Config {
    let mut config = client::Config::default();
    config.keepalive_interval = Some(Duration::from_secs(15));
    config.keepalive_max = 4;
    config
}

pub fn default_client_config() -> Arc<client::Config> {
    Arc::new(base_client_config())
}

/// Client config for a connection to `address:port`. When a host key is
/// already trusted for it, that key's algorithm goes first in the host-key
/// preference list (as OpenSSH does), so the server presents the same kind of
/// key we pinned (say, one pinned before the server got an Ed25519 key) rather
/// than a different type that would trip the "host key changed" check.
pub fn client_config_for(db: &Database, address: &str, port: u16) -> Arc<client::Config> {
    let mut config = base_client_config();
    if let Ok(Some(known)) = db.get_known_host(address, port) {
        config.preferred.key = std::borrow::Cow::Owned(prefer_host_key_algorithm(&config.preferred.key, &known.key_type));
    }
    Arc::new(config)
}

fn prefer_host_key_algorithm(order: &[russh::keys::Algorithm], key_type: &str) -> Vec<russh::keys::Algorithm> {
    use russh::keys::Algorithm;
    let Ok(pinned) = Algorithm::new(key_type) else {
        return order.to_vec();
    };
    // Every RSA signature variant (rsa-sha2-512/256, ssh-rsa) uses the same key.
    let same_kind = |a: &Algorithm| matches!((&pinned, a), (Algorithm::Rsa { .. }, Algorithm::Rsa { .. })) || *a == pinned;
    order
        .iter()
        .filter(|a| same_kind(a))
        .chain(order.iter().filter(|a| !same_kind(a)))
        .cloned()
        .collect()
}

/// Progress payload emitted to the frontend during connection handshake.
#[derive(Debug, Clone, Serialize)]
pub struct SshProgressPayload {
    pub step: u8,          // 1: Connect, 2: HostKey, 3: Auth, 4: Shell, 5: Ready
    pub step_name: String, // "connecting", "host_key", "authenticating", "opening_channel", "ready", "error"
    pub message: String,
    pub timestamp: String,
    pub is_error: bool,
}

/// Verifies the server's host key against the locally stored known_hosts
/// table (Trust On First Use), rejecting the connection outright if the
/// key ever changes for a previously trusted address:port — this is the
/// same protection OpenSSH's known_hosts file provides against MITM
/// attacks and impersonated servers.
pub struct SshClientHandler {
    pub address: String,
    pub port: u16,
    pub db: Arc<Database>,
    /// Where connections from a remote port forward (`ssh -R`) are handed
    /// off. `None` on connections that never requested one: any
    /// forwarded-tcpip channel the server opens there is closed.
    pub forwarded_tcpip: Option<mpsc::UnboundedSender<ForwardedTcpip>>,
}

/// A connection the server accepted on a remote-forwarded port, delivered to
/// the client as a `forwarded-tcpip` channel.
pub struct ForwardedTcpip {
    pub channel: russh::Channel<client::Msg>,
    pub connected_address: String,
    pub connected_port: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

impl Handler for SshClientHandler {
    type Error = anyhow::Error;

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let forwarded = ForwardedTcpip {
            channel,
            connected_address: connected_address.to_string(),
            connected_port,
            originator_address: originator_address.to_string(),
            originator_port,
        };
        let rejected = match &self.forwarded_tcpip {
            Some(tx) => tx.send(forwarded).err().map(|e| e.0),
            None => Some(forwarded),
        };
        // Nobody is serving forwards on this connection (never requested, or
        // the tunnel already stopped): refuse instead of leaving it hanging.
        if let Some(forwarded) = rejected {
            let _ = forwarded.channel.close().await;
        }
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = format!("{}", server_public_key.fingerprint(HashAlg::Sha256));
        let key_type = server_public_key.algorithm().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        // Fail closed: a DB error must never be treated as "host never seen",
        // otherwise the presented (possibly attacker) key would get pinned.
        let existing = self
            .db
            .get_known_host(&self.address, self.port)
            .map_err(|e| anyhow::anyhow!("Could not read known hosts to verify the server key: {e}"))?;

        match existing {
            None => {
                // Trust On First Use: remember this key for future connections.
                let entry = KnownHost {
                    address: self.address.clone(),
                    port: self.port,
                    key_type,
                    fingerprint,
                    first_seen_at: now.clone(),
                    last_seen_at: now,
                };
                // If we can't pin the key, don't proceed: the next connection
                // would silently TOFU again and accept whatever key it sees.
                self.db
                    .save_known_host(&entry)
                    .map_err(|e| anyhow::anyhow!("Could not save the server key to known hosts: {e}"))?;
                Ok(true)
            }
            Some(known) if known.fingerprint == fingerprint => {
                // Key matches what we trusted before — refresh last_seen_at.
                let mut updated = known;
                updated.last_seen_at = now;
                let _ = self.db.save_known_host(&updated);
                Ok(true)
            }
            Some(known) => {
                // Key mismatch: potential MITM attack, server reinstall, or IP reuse.
                Err(anyhow::anyhow!(
                    "REMOTE HOST IDENTIFICATION HAS CHANGED for {}:{}! Server presented a key with fingerprint {} but the previously trusted key was {} (first trusted {}). This could indicate a man-in-the-middle attack, or the server may have been reinstalled. Remove the old entry from Known Hosts if you trust this change.",
                    self.address, self.port, fingerprint, known.fingerprint, known.first_seen_at
                ))
            }
        }
    }
}

#[derive(Clone)]
pub enum SshAuth {
    Password(String),
    /// No password saved for the host: ask for it at every login.
    AskPassword,
    PrivateKey { pem: String, passphrase: Option<String> },
}

#[derive(Clone)]
pub struct JumpHostConfig {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
}

pub enum SshStream {
    Direct(tokio::net::TcpStream),
    Tunneled(russh::ChannelStream<russh::client::Msg>),
}

impl tokio::io::AsyncRead for SshStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SshStream::Direct(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            SshStream::Tunneled(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for SshStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            SshStream::Direct(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            SshStream::Tunneled(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SshStream::Direct(s) => std::pin::Pin::new(s).poll_flush(cx),
            SshStream::Tunneled(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SshStream::Direct(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            SshStream::Tunneled(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub enum SessionCommand {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
}

/// Authenticates an SSH session using public key authentication, dynamically negotiating
/// the strongest RSA signature algorithm (rsa-sha2-512, rsa-sha2-256) accepted by the
/// server with fallback to sha-1, avoiding the "Authentication rejected" error seen on
/// modern OpenSSH (>= 8.8) servers that disable legacy SHA-1 ssh-rsa.
pub async fn authenticate_publickey_smart<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    username: &str,
    key_pair: russh::keys::PrivateKey,
) -> Result<russh::client::AuthResult, String> {
    let is_rsa = key_pair.algorithm().is_rsa();
    let best_hash = if is_rsa {
        match handle.best_supported_rsa_hash().await {
            Ok(Some(hash)) => hash,
            _ => Some(HashAlg::Sha512),
        }
    } else {
        None
    };

    let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair.clone()), best_hash);
    let mut res = handle
        .authenticate_publickey(username, key)
        .await
        .map_err(|e| format!("Auth error: {e}"))?;

    // Retry other RSA signature hashes only while the server still offers
    // publickey: if it doesn't, or the key was accepted as a first factor
    // (e.g. `AuthenticationMethods publickey,keyboard-interactive`), or
    // publickey is disabled, retrying can't help.
    let still_offers_publickey = matches!(
        &res,
        AuthResult::Failure { remaining_methods, partial_success: false }
            if remaining_methods.contains(&MethodKind::PublicKey)
    );
    if is_rsa && still_offers_publickey {
        for fallback in [Some(HashAlg::Sha256), Some(HashAlg::Sha512), None] {
            if fallback == best_hash {
                continue;
            }
            let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair.clone()), fallback);
            if let Ok(r) = handle.authenticate_publickey(username, key).await {
                if r.success() {
                    res = r;
                    break;
                }
            }
        }
    }

    Ok(res)
}

/// Authenticate with the stored credential, asking the user through the UI
/// for anything else the server wants (see [`authenticate_with`]).
/// `target` names the login in prompts, e.g. "root@10.0.0.5".
async fn authenticate(
    handle: &mut Handle<SshClientHandler>,
    username: &str,
    auth: &SshAuth,
    target: &str,
) -> Result<bool, String> {
    authenticate_with(handle, username, auth, target, &UiPrompter).await
}

/// Authenticate with the stored password or key, then continue with
/// keyboard-interactive when the server lists it as a remaining method:
/// two-factor setups (`AuthenticationMethods publickey,keyboard-interactive`,
/// PAM password + OTP, Duo) and servers that only take passwords through
/// keyboard-interactive. Prompts the stored password can't answer go to
/// `prompter`.
pub(crate) async fn authenticate_with<P: AuthPrompter>(
    handle: &mut Handle<SshClientHandler>,
    username: &str,
    auth: &SshAuth,
    target: &str,
    prompter: &P,
) -> Result<bool, String> {
    // `password` answers a keyboard-interactive "Password:" prompt later on.
    let (first, password) = match auth {
        SshAuth::Password(password) => {
            let result = handle
                .authenticate_password(username, password)
                .await
                .map_err(|e| format!("Auth error: {e}"))?;
            (result, Some(Zeroizing::new(password.clone())))
        }
        SshAuth::AskPassword => ask_password_login(handle, username, target, prompter).await?,
        SshAuth::PrivateKey { pem, passphrase } => {
            let key_pair = load_private_key(pem, passphrase.as_deref(), target, prompter).await?;
            (authenticate_publickey_smart(handle, username, key_pair).await?, None)
        }
    };
    match first {
        AuthResult::Success => Ok(true),
        AuthResult::Failure { remaining_methods, .. } if remaining_methods.contains(&MethodKind::KeyboardInteractive) => {
            keyboard_interactive(handle, username, password, target, prompter).await
        }
        AuthResult::Failure { .. } => Ok(false),
    }
}

/// Ask the user for one hidden value; `None` from the prompter cancels the login.
async fn ask_secret<P: AuthPrompter>(
    prompter: &P,
    target: &str,
    title: &str,
    instructions: &str,
    label: &str,
) -> Result<Zeroizing<String>, String> {
    let request = AuthPromptRequest {
        target: target.to_string(),
        name: title.to_string(),
        instructions: instructions.to_string(),
        prompts: vec![PromptField { prompt: label.to_string(), echo: false }],
    };
    prompter
        .ask(request)
        .await
        .and_then(|answers| answers.into_iter().next())
        .map(Zeroizing::new)
        .ok_or_else(|| "Authentication cancelled".to_string())
}

/// Password login for a host without a saved password. The user is only asked
/// when the server takes the `password` method; one that takes passwords
/// through keyboard-interactive alone asks with its own prompt afterwards.
/// Returns the last password typed, for that keyboard-interactive round.
async fn ask_password_login<P: AuthPrompter>(
    handle: &mut Handle<SshClientHandler>,
    username: &str,
    target: &str,
    prompter: &P,
) -> Result<(AuthResult, Option<Zeroizing<String>>), String> {
    let auth_error = |e: russh::Error| format!("Auth error: {e}");
    let mut result = handle.authenticate_none(username).await.map_err(auth_error)?;
    let mut typed = None;
    for attempt in 0..SECRET_ATTEMPTS {
        let AuthResult::Failure { remaining_methods, .. } = &result else { break };
        if !remaining_methods.contains(&MethodKind::Password) {
            break;
        }
        let instructions = if attempt == 0 { "" } else { "Wrong password, try again." };
        let password = ask_secret(prompter, target, "Password", instructions, "Password").await?;
        result = handle
            .authenticate_password(username, password.as_str())
            .await
            .map_err(auth_error)?;
        typed = Some(password);
    }
    Ok((result, typed))
}

/// Decode a saved key. An encrypted key saved without its passphrase asks
/// for it, like ssh does.
async fn load_private_key<P: AuthPrompter>(
    pem: &str,
    passphrase: Option<&str>,
    target: &str,
    prompter: &P,
) -> Result<russh::keys::PrivateKey, String> {
    match decode_secret_key(pem, passphrase) {
        Err(e) if passphrase.is_none() && crate::sshkey::is_missing_passphrase(pem, &e) => {}
        decoded => return decoded.map_err(|e| format!("Invalid private key: {e}")),
    }
    for attempt in 0..SECRET_ATTEMPTS {
        let instructions = if attempt == 0 { "The private key is encrypted." } else { "Wrong passphrase, try again." };
        let typed = ask_secret(prompter, target, "Key passphrase", instructions, "Passphrase").await?;
        if let Ok(key) = decode_secret_key(pem, Some(typed.as_str())) {
            return Ok(key);
        }
    }
    Err("Wrong passphrase for the private key".to_string())
}

async fn keyboard_interactive<P: AuthPrompter>(
    handle: &mut Handle<SshClientHandler>,
    username: &str,
    mut stored_password: Option<Zeroizing<String>>,
    target: &str,
    prompter: &P,
) -> Result<bool, String> {
    let kbd_error = |e: russh::Error| format!("Keyboard-interactive auth error: {e}");
    let mut response = handle
        .authenticate_keyboard_interactive_start(username, None::<String>)
        .await
        .map_err(kbd_error)?;

    for _ in 0..MAX_KBD_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                let fields: Vec<PromptField> = prompts
                    .into_iter()
                    .map(|p| PromptField { prompt: p.prompt, echo: p.echo })
                    .collect();
                let (mut answers, ask) = auth_prompt::plan_answers(&fields, &mut stored_password);
                if !ask.is_empty() {
                    let request = AuthPromptRequest {
                        target: target.to_string(),
                        name,
                        instructions,
                        prompts: ask.iter().map(|&i| fields[i].clone()).collect(),
                    };
                    let user_answers = prompter
                        .ask(request)
                        .await
                        .filter(|a| a.len() == ask.len())
                        .ok_or_else(|| "Authentication cancelled".to_string())?;
                    for (index, answer) in ask.into_iter().zip(user_answers) {
                        answers[index] = Some(answer);
                    }
                }
                // Servers may also send rounds with no prompts at all.
                let answers = answers.into_iter().map(Option::unwrap_or_default).collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(kbd_error)?;
            }
        }
    }
    Err("The server kept asking for more input; giving up".to_string())
}

/// Open a raw byte stream to `address:port`: a direct TCP connection, or a
/// `direct-tcpip` channel through `jump` (ProxyJump) when the host sits behind
/// a bastion. The jump hop is authenticated and TOFU-verified through
/// `SshClientHandler`. Used for the SSH transport itself and for non-SSH
/// protocols (VNC) that ride on the same bastion.
///
/// The returned jump handle must be kept alive while the stream is in use.
pub async fn open_transport(
    db: Arc<Database>,
    address: &str,
    port: u16,
    jump: Option<&JumpHostConfig>,
) -> Result<(SshStream, Option<Handle<SshClientHandler>>), String> {
    match jump {
        Some(jump) => {
            let jump_tcp = tokio::net::TcpStream::connect((jump.address.as_str(), jump.port))
                .await
                .map_err(|e| format!("Failed to reach Jump Host {}:{}: {e}", jump.address, jump.port))?;
            configure_tcp_stream(&jump_tcp);
            let jump_config = client_config_for(&db, &jump.address, jump.port);
            let jump_handler = SshClientHandler {
                address: jump.address.clone(),
                port: jump.port,
                db,
                forwarded_tcpip: None,
            };
            let mut j_handle = client::connect_stream(jump_config, jump_tcp, jump_handler)
                .await
                .map_err(|e| format!("Jump Host handshake failed: {e}"))?;
            let jump_target = format!("{}@{} (jump host)", jump.username, jump.address);
            if !authenticate(&mut j_handle, &jump.username, &jump.auth, &jump_target)
                .await
                .map_err(|e| format!("Jump Host {e}"))?
            {
                return Err("Jump Host authentication rejected by server".to_string());
            }
            let channel = j_handle
                .channel_open_direct_tcpip(address.to_string(), port as u32, "127.0.0.1".to_string(), 0)
                .await
                .map_err(|e| format!("Failed to open tunnel through Jump Host to {address}:{port}: {e}"))?;
            Ok((SshStream::Tunneled(channel.into_stream()), Some(j_handle)))
        }
        None => {
            let tcp = tokio::net::TcpStream::connect((address, port))
                .await
                .map_err(|e| format!("TCP connection to {address}:{port} failed: {e}"))?;
            configure_tcp_stream(&tcp);
            Ok((SshStream::Direct(tcp), None))
        }
    }
}

/// Open an authenticated SSH connection to `address:port`, hopping through
/// `jump` (ProxyJump) when the host is configured behind a bastion. Used by
/// SFTP and tunnels; the terminal path (`do_connect`) does the same steps with
/// progress events and cancel checkpoints. Both hops go through
/// `SshClientHandler`, so TOFU host key verification applies to each.
///
/// Returns the target handle and the jump handle, which must be kept alive
/// for as long as the target connection is in use.
pub async fn connect_authenticated(
    db: Arc<Database>,
    address: &str,
    port: u16,
    username: &str,
    auth: &SshAuth,
    jump: Option<&JumpHostConfig>,
) -> Result<(Handle<SshClientHandler>, Option<Handle<SshClientHandler>>), String> {
    connect_authenticated_with_forwarding(db, address, port, username, auth, jump, None).await
}

/// Like [`connect_authenticated`], but hands channels the server opens for
/// remote port forwards (`tcpip-forward` requests made on this connection)
/// to `forwarded_tcpip`.
pub async fn connect_authenticated_with_forwarding(
    db: Arc<Database>,
    address: &str,
    port: u16,
    username: &str,
    auth: &SshAuth,
    jump: Option<&JumpHostConfig>,
    forwarded_tcpip: Option<mpsc::UnboundedSender<ForwardedTcpip>>,
) -> Result<(Handle<SshClientHandler>, Option<Handle<SshClientHandler>>), String> {
    let (stream, jump_handle) = open_transport(db.clone(), address, port, jump).await?;

    let config = client_config_for(&db, address, port);
    let handler = SshClientHandler {
        address: address.to_string(),
        port,
        db,
        forwarded_tcpip,
    };
    let mut handle = client::connect_stream(config, stream, handler)
        .await
        .map_err(|e| format!("SSH connection failed: {e}"))?;
    if !authenticate(&mut handle, username, auth, &format!("{username}@{address}")).await? {
        return Err("Authentication rejected by server".to_string());
    }
    Ok((handle, jump_handle))
}

pub struct SshSession {
    pub id: String,
    handle: Handle<SshClientHandler>,
    cmd_tx: mpsc::UnboundedSender<SessionCommand>,
    _jump_handle: Option<Handle<SshClientHandler>>,
}

pub struct SessionManager {
    sessions: RwLock<HashMap<String, Arc<SshSession>>>,
    connecting: Mutex<HashSet<String>>,
    /// Session ids whose connect is in flight but whose tab was already closed.
    /// `disconnect()` marks them here so the running `do_connect` aborts at its
    /// next checkpoint instead of leaving a zombie connection behind.
    cancelled: Mutex<HashSet<String>>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: RwLock::new(HashMap::new()),
            connecting: Mutex::new(HashSet::new()),
            cancelled: Mutex::new(HashSet::new()),
        }
    }

    pub async fn connect(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        session_id: String,
        host_id: Option<String>,
        address: String,
        port: u16,
        username: String,
        auth: SshAuth,
        cols: u16,
        rows: u16,
        jump_host: Option<JumpHostConfig>,
    ) -> Result<(), String> {
        // Prevent duplicate concurrent connection attempts for the exact same session_id
        {
            let mut connecting = self.connecting.lock().await;
            if connecting.contains(&session_id) {
                return Err("Connection already in progress for this session".to_string());
            }
            connecting.insert(session_id.clone());
        }

        // Fresh attempt (e.g. Retry after a cancelled connect): drop any stale
        // cancel mark left behind by a previous aborted attempt for this id.
        {
            let mut cancelled = self.cancelled.lock().await;
            cancelled.remove(&session_id);
        }

        // Clean up any stale existing session with this ID before starting fresh
        {
            let mut sessions = self.sessions.write().await;
            if let Some(old_session) = sessions.remove(&session_id) {
                let _ = old_session.handle.disconnect(Disconnect::ByApplication, "", "en").await;
                if let Some(ref jump) = old_session._jump_handle {
                    let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
                }
            }
        }

        let res = self
            .do_connect(app, db, session_id.clone(), host_id, address, port, username, auth, cols, rows, jump_host)
            .await;

        {
            let mut connecting = self.connecting.lock().await;
            connecting.remove(&session_id);
        }

        // A cancel can land in the gap between the last checkpoint inside
        // do_connect and the session being registered in the map. If so, the
        // session was fully established for a tab that no longer exists —
        // close it immediately instead of leaking the connection.
        let was_cancelled = {
            let mut cancelled = self.cancelled.lock().await;
            cancelled.remove(&session_id)
        };
        match res {
            Ok(()) if was_cancelled => {
                let _ = self.disconnect(&session_id).await;
                Err("Connection cancelled".to_string())
            }
            other => other,
        }
    }

    /// Returns `Err` when the tab for this session was closed while the
    /// connect was still in flight (`disconnect()` marked it as cancelled).
    async fn check_cancelled(&self, session_id: &str) -> Result<(), String> {
        if self.cancelled.lock().await.contains(session_id) {
            Err("Connection cancelled".to_string())
        } else {
            Ok(())
        }
    }

    async fn do_connect(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        session_id: String,
        host_id: Option<String>,
        address: String,
        port: u16,
        username: String,
        auth: SshAuth,
        cols: u16,
        rows: u16,
        jump_host: Option<JumpHostConfig>,
    ) -> Result<(), String> {
        self.check_cancelled(&session_id).await?;

        let progress_event = format!("ssh-progress-{session_id}");
        let emit_progress = |step: u8, step_name: &str, message: &str, is_error: bool| {
            let _ = app.emit(
                &progress_event,
                SshProgressPayload {
                    step,
                    step_name: step_name.to_string(),
                    message: message.to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    is_error,
                },
            );
        };

        // ── 1. Establish Transport Stream (Direct TCP or via Jump Host ProxyJump) ──
        let (socket, jump_handle) = if let Some(jump) = jump_host {
            emit_progress(1, "connecting", &format!("Connecting to Bastion / Jump Host {}:{}...", jump.address, jump.port), false);

            let jump_tcp = match tokio::net::TcpStream::connect((jump.address.as_str(), jump.port)).await {
                Ok(s) => {
                    configure_tcp_stream(&s);
                    s
                }
                Err(e) => {
                    let msg = format!("Failed to reach Jump Host {}:{}: {e}", jump.address, jump.port);
                    emit_progress(1, "error", &msg, true);
                    return Err(msg);
                }
            };

            self.check_cancelled(&session_id).await?;

            let jump_config = client_config_for(&db, &jump.address, jump.port);
            let jump_handler = SshClientHandler {
                address: jump.address.clone(),
                port: jump.port,
                db: db.clone(),
                forwarded_tcpip: None,
            };

            let mut j_handle = match client::connect_stream(jump_config, jump_tcp, jump_handler).await {
                Ok(h) => h,
                Err(e) => {
                    let msg = format!("Jump Host handshake failed: {e}");
                    emit_progress(1, "error", &msg, true);
                    return Err(msg);
                }
            };

            self.check_cancelled(&session_id).await?;

            emit_progress(1, "authenticating", &format!("Authenticating to Jump Host as {}...", jump.username), false);

            let jump_target = format!("{}@{} (jump host)", jump.username, jump.address);
            match authenticate(&mut j_handle, &jump.username, &jump.auth, &jump_target).await {
                Ok(true) => {}
                Ok(false) => {
                    let msg = "Jump Host authentication rejected by server".to_string();
                    emit_progress(1, "error", &msg, true);
                    return Err(msg);
                }
                Err(e) => {
                    let msg = format!("Jump Host {e}");
                    emit_progress(1, "error", &msg, true);
                    return Err(msg);
                }
            }

            self.check_cancelled(&session_id).await?;

            emit_progress(1, "connecting", &format!("Tunneling via Jump Host to {address}:{port}..."), false);

            let channel = match j_handle.channel_open_direct_tcpip(
                address.clone(),
                port as u32,
                "127.0.0.1".to_string(),
                0,
            ).await {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("Failed to open tunnel through Jump Host to {address}:{port}: {e}");
                    emit_progress(1, "error", &msg, true);
                    return Err(msg);
                }
            };

            self.check_cancelled(&session_id).await?;

            (SshStream::Tunneled(channel.into_stream()), Some(j_handle))
        } else {
            emit_progress(1, "connecting", &format!("Resolving and connecting to {address}:{port}..."), false);

            let s = match tokio::net::TcpStream::connect((address.as_str(), port)).await {
                Ok(s) => {
                    configure_tcp_stream(&s);
                    s
                }
                Err(e) => {
                    let msg = format!("Connection failed: {e}");
                    emit_progress(1, "error", &msg, true);
                    return Err(msg);
                }
            };
            self.check_cancelled(&session_id).await?;

            (SshStream::Direct(s), None)
        };

        // ── 2. Target SSH Handshake over the stream ──
        let config = client_config_for(&db, &address, port);
        let handler = SshClientHandler {
            address: address.clone(),
            port,
            db: db.clone(),
            forwarded_tcpip: None,
        };

        let mut handle = match client::connect_stream(config, socket, handler).await {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("Connection to target failed: {e}");
                emit_progress(1, "error", &msg, true);
                return Err(msg);
            }
        };

        self.check_cancelled(&session_id).await?;

        emit_progress(2, "host_key", "Verifying target host key (Trust On First Use)...", false);

        emit_progress(3, "authenticating", &format!("Authenticating as {username}..."), false);

        // Keyboard-interactive (2FA codes etc.) is asked through the UI here
        // when the server wants more than the stored password or key.
        match authenticate(&mut handle, &username, &auth, &format!("{username}@{address}")).await {
            Ok(true) => {}
            Ok(false) => {
                let msg = "Authentication rejected by server".to_string();
                emit_progress(3, "error", &msg, true);
                return Err(msg);
            }
            Err(msg) => {
                emit_progress(3, "error", &msg, true);
                return Err(msg);
            }
        }

        self.check_cancelled(&session_id).await?;

        emit_progress(4, "opening_channel", "Opening shell channel...", false);

        let channel = match handle.channel_open_session().await {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("Channel open failed: {e}");
                emit_progress(4, "error", &msg, true);
                return Err(msg);
            }
        };

        self.check_cancelled(&session_id).await?;

        if let Err(e) = channel
            .request_pty(true, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
            .await
        {
            let msg = format!("PTY request failed: {e}");
            emit_progress(4, "error", &msg, true);
            return Err(msg);
        }

        if let Err(e) = channel.request_shell(true).await {
            let msg = format!("Shell request failed: {e}");
            emit_progress(4, "error", &msg, true);
            return Err(msg);
        }

        // Last checkpoint before registration: past this point the session is
        // live in the map, so a late cancel is handled by the connect() wrapper.
        self.check_cancelled(&session_id).await?;

        emit_progress(5, "ready", "Shell session ready.", false);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SessionCommand>();

        let session = Arc::new(SshSession {
            id: session_id.clone(),
            handle,
            cmd_tx,
            _jump_handle: jump_handle,
        });

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }

        let event_name = format!("ssh-data-{session_id}");
        let closed_event = format!("ssh-closed-{session_id}");
        let app_for_output = app.clone();
        let sid_for_output = session_id.clone();

        // Worker task: stream server output to frontend & handle incoming commands (write & resize)
        tokio::spawn(async move {
            let mut channel = channel;
            // Adaptive output coalescing:
            // 1. When the channel is idle (interactive keystroke echo, prompt display),
            //    emit immediately (0ms latency) and start a short cooldown timer.
            // 2. Any subsequent bursts of output arriving within the cooldown (e.g. cat,
            //    htop, build logs) are accumulated into `pending` and emitted in ~8ms batches
            //    (or at 64KB cap) to prevent saturating Tauri's IPC event bridge.
            let mut pending: Vec<u8> = Vec::new();
            let flush_delay = tokio::time::Duration::from_millis(8);
            let mut flush_deadline: Option<tokio::time::Instant> = None;

            loop {
                let sleep = async {
                    match flush_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                };

                tokio::select! {
                    msg = channel.wait() => {
                        match msg {
                            Some(russh::ChannelMsg::Data { ref data }) => {
                                match flush_deadline {
                                    None => {
                                        // Idle stream: emit interactive echo immediately (0ms delay)
                                        let _ = app_for_output.emit(&event_name, data.to_vec());
                                        flush_deadline = Some(tokio::time::Instant::now() + flush_delay);
                                    }
                                    Some(_) => {
                                        pending.extend_from_slice(data);
                                        if pending.len() >= 64 * 1024 {
                                            let _ = app_for_output.emit(&event_name, std::mem::take(&mut pending));
                                            flush_deadline = None;
                                        }
                                    }
                                }
                            }
                            Some(russh::ChannelMsg::ExtendedData { ref data, .. }) => {
                                match flush_deadline {
                                    None => {
                                        let _ = app_for_output.emit(&event_name, data.to_vec());
                                        flush_deadline = Some(tokio::time::Instant::now() + flush_delay);
                                    }
                                    Some(_) => {
                                        pending.extend_from_slice(data);
                                        if pending.len() >= 64 * 1024 {
                                            let _ = app_for_output.emit(&event_name, std::mem::take(&mut pending));
                                            flush_deadline = None;
                                        }
                                    }
                                }
                            }
                            Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => {
                                if !pending.is_empty() {
                                    let _ = app_for_output.emit(&event_name, std::mem::take(&mut pending));
                                }
                                let _ = app_for_output.emit(&closed_event, sid_for_output.clone());
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ = sleep => {
                        if !pending.is_empty() {
                            let _ = app_for_output.emit(&event_name, std::mem::take(&mut pending));
                        }
                        flush_deadline = None;
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(SessionCommand::Data(data)) => {
                                let _ = channel.data(&data[..]).await;
                            }
                            Some(SessionCommand::Resize { cols, rows }) => {
                                // Safeguard: Ignore 0 or near-zero window sizes caused by hidden DOM elements
                                if cols >= 15 && rows >= 4 {
                                    let _ = channel.window_change(cols, rows, 0, 0).await;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        // Detect the OS over this same connection (a second exec channel): no
        // extra login — which would ask for a 2FA code again — and it works
        // behind jump hosts too. Fire-and-forget; failures are ignored.
        if let Some(hid) = host_id {
            let app_for_os = app.clone();
            let db_for_os = db.clone();
            let session_for_os = Arc::downgrade(&session);
            tokio::spawn(async move {
                // Let the interactive shell settle before opening a second channel.
                tokio::time::sleep(Duration::from_millis(800)).await;
                detect_os_via_exec(&app_for_os, db_for_os, session_for_os, hid).await;
            });
        }

        Ok(())
    }

    pub async fn write(&self, session_id: &str, data: Vec<u8>) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        session
            .cmd_tx
            .send(SessionCommand::Data(data))
            .map_err(|e| format!("Failed to send input: {e}"))
    }

    pub async fn resize(&self, session_id: &str, cols: u16, rows: u16) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        session
            .cmd_tx
            .send(SessionCommand::Resize {
                cols: cols as u32,
                rows: rows as u32,
            })
            .map_err(|e| format!("Failed to send resize: {e}"))
    }

    pub async fn disconnect(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(session_id) {
            let _ = session
                .handle
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
            // Close the bastion connection too (mirrors the stale-session
            // cleanup in connect()), instead of relying on drop alone.
            if let Some(ref jump) = session._jump_handle {
                let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
            }
        } else if self.connecting.lock().await.contains(session_id) {
            // No registered session, but a connect is in flight for this id —
            // the tab was closed mid-connect. Mark it so do_connect aborts at
            // its next checkpoint (and so a session established in the gap
            // between checkpoints is caught by connect()'s final check).
            self.cancelled.lock().await.insert(session_id.to_string());
        }
        Ok(())
    }

    /// Disconnects every live SSH session. Used for a clean shutdown when the
    /// application exits, so servers see a proper SSH disconnect message
    /// instead of a dropped TCP socket.
    pub async fn disconnect_all(&self) {
        let ids: Vec<String> = {
            let sessions = self.sessions.read().await;
            sessions.keys().cloned().collect()
        };
        for id in ids {
            let _ = self.disconnect(&id).await;
        }
    }
}

/// Parse the output of `cat /etc/os-release` and map it to one of our
/// canonical distro slugs, which the frontend uses to pick an icon.
/// Returns `None` when OS detection fails or the output is unrecognisable.
pub fn parse_os_release(output: &str) -> Option<String> {
    // Extract the value of a KEY="value" or KEY=value line.
    let get = |key: &str| -> Option<String> {
        output.lines().find_map(|line| {
            let line = line.trim();
            let prefix = format!("{key}=");
            if line.starts_with(&prefix) {
                let val = line[prefix.len()..].trim_matches('"').to_lowercase();
                Some(val)
            } else {
                None
            }
        })
    };

    // Prefer ID_LIKE (parent distro), fall back to ID.
    let id = get("ID").unwrap_or_default();
    let id_like = get("ID_LIKE").unwrap_or_default();
    let pretty = get("PRETTY_NAME").unwrap_or_default();
    let name = get("NAME").unwrap_or_default();

    let combined = format!("{id} {id_like} {pretty} {name}");

    if combined.contains("ubuntu") {
        Some("ubuntu".to_string())
    } else if combined.contains("kali") {
        Some("kali".to_string())
    } else if combined.contains("mint") {
        Some("mint".to_string())
    } else if combined.contains("pop!_os") || combined.contains("pop_os") || combined.contains("popos") {
        Some("popos".to_string())
    } else if combined.contains("elementary") {
        Some("elementary".to_string())
    } else if combined.contains("debian") {
        Some("debian".to_string())
    } else if combined.contains("alpine") {
        Some("alpine".to_string())
    } else if combined.contains("arch") || combined.contains("manjaro") || combined.contains("endeavouros") || combined.contains("endeavour") {
        if combined.contains("manjaro") {
            Some("manjaro".to_string())
        } else if combined.contains("endeavouros") || combined.contains("endeavour") {
            Some("endeavour".to_string())
        } else {
            Some("arch".to_string())
        }
    } else if combined.contains("fedora") {
        Some("fedora".to_string())
    } else if combined.contains("rocky") {
        Some("rocky".to_string())
    } else if combined.contains("almalinux") || combined.contains("alma") {
        Some("almalinux".to_string())
    } else if combined.contains("centos") {
        Some("centos".to_string())
    } else if combined.contains("rhel") || combined.contains("red hat") || combined.contains("redhat") {
        Some("rhel".to_string())
    } else if combined.contains("opensuse") || combined.contains("suse") {
        Some("opensuse".to_string())
    } else if combined.contains("gentoo") {
        Some("gentoo".to_string())
    } else if combined.contains("nixos") {
        Some("nixos".to_string())
    } else if combined.contains("void") {
        Some("void".to_string())
    } else if combined.contains("raspbian") || combined.contains("raspberry") {
        Some("raspbian".to_string())
    } else if combined.contains("slackware") {
        Some("slackware".to_string())
    } else if combined.contains("amazon") || combined.contains("amzn") {
        Some("amazon".to_string())
    } else if !id.is_empty() {
        // Known to be Linux (has /etc/os-release) but distro unrecognised
        Some("linux".to_string())
    } else {
        None
    }
}

/// Open a fresh exec channel (not reusing the interactive PTY) and run
/// `cat /etc/os-release`.  Returns the detected distro slug, or `None`
/// on any failure — this never propagates errors to the caller.
/// Read `/etc/os-release` over an existing session (a separate exec channel)
/// and store the distro icon for the host.
pub async fn detect_os_via_exec(app: &AppHandle, db: Arc<Database>, session: Weak<SshSession>, host_id: String) {
    // The tab may already be closed.
    let Some(session) = session.upgrade() else { return };
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut channel = session
            .handle
            .channel_open_session()
            .await
            .map_err(|e| e.to_string())?;
        channel
            .exec(true, "cat /etc/os-release")
            .await
            .map_err(|e| e.to_string())?;

        let mut output = String::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { ref data }) => {
                    output.push_str(&String::from_utf8_lossy(data));
                    if output.len() > 8192 {
                        break;
                    }
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
        // The channel isn't closed from our side: the server closes it when
        // the command exits (closing first raced with its late window
        // adjusts, which dropped the whole connection before russh 0.54).
        Ok::<_, String>(parse_os_release(&output))
    })
    .await;
    drop(session);

    if let Ok(Ok(Some(slug))) = result {
        if let Ok(()) = db.update_host_os_icon(&host_id, &slug) {
            let _ = app.emit(
                "host-os-detected",
                serde_json::json!({ "host_id": host_id, "os_icon": slug }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncRead, AsyncWrite};

    #[test]
    fn pinned_host_key_algorithm_is_negotiated_first() {
        use russh::keys::Algorithm;
        let default = super::base_client_config().preferred.key.to_vec();
        assert_eq!(default[0], Algorithm::Ed25519);

        let ecdsa = super::prefer_host_key_algorithm(&default, "ecdsa-sha2-nistp256");
        assert_eq!(ecdsa[0].as_str(), "ecdsa-sha2-nistp256");
        assert_eq!(ecdsa.len(), default.len());

        // A pinned RSA key moves every RSA signature variant up front.
        let rsa = super::prefer_host_key_algorithm(&default, "ssh-rsa");
        assert!(rsa[..3].iter().all(|a| matches!(a, Algorithm::Rsa { .. })));

        assert_eq!(super::prefer_host_key_algorithm(&default, "bogus"), default);
    }

    fn _assert_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>() {}

    #[test]
    fn test_channel_into_stream_trait() {
        _assert_stream::<russh::ChannelStream<russh::client::Msg>>();
    }
}
