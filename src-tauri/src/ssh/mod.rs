use russh::client::{self, Handle, Handler};
use russh::keys::ssh_key::HashAlg;
use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::db::models::KnownHost;
use crate::db::Database;
pub use conn::{ConnectionPool, Hop, Route, SshConnection};
use auth_prompt::{AuthPromptRequest, AuthPrompter, PromptField, UiPrompter};
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::MethodKind;
use zeroize::Zeroizing;

pub mod auth_prompt;
#[cfg(test)]
mod auth_tests;
pub mod conn;
pub mod totp;
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
    /// Where connections from remote port forwards (`ssh -R`) go, by the
    /// port the server listens on. Channels for a port nobody asked for, or
    /// whose tunnel already stopped, are closed.
    pub forwards: Arc<conn::ForwardRouter>,
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
        let rejected = match self.forwards.sender(connected_address, connected_port) {
            Some(tx) => tx.send(forwarded).err().map(|e| e.0),
            None => Some(forwarded),
        };
        // Nobody is serving this port (never requested, or the tunnel already
        // stopped): refuse instead of leaving it hanging.
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
    totp: Option<&totp::Totp>,
    target: &str,
) -> Result<bool, String> {
    authenticate_with(handle, username, auth, totp, target, &UiPrompter).await
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
    totp: Option<&totp::Totp>,
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
            keyboard_interactive(handle, username, password, totp.cloned(), target, prompter).await
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
    mut totp: Option<totp::Totp>,
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
                let (mut answers, ask) = auth_prompt::plan_answers(&fields, &mut stored_password, &mut totp);
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

pub struct SshSession {
    pub id: String,
    /// Possibly shared with other tabs, SFTP and tunnels to the same host.
    connection: Arc<SshConnection>,
    cmd_tx: mpsc::UnboundedSender<SessionCommand>,
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

    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        pool: &ConnectionPool,
        session_id: String,
        host_id: Option<String>,
        route: Route,
        cols: u16,
        rows: u16,
        command: Option<String>,
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

        // A stale session with this id (a retry) closes its shell when dropped.
        self.sessions.write().await.remove(&session_id);

        let res = self
            .do_connect(app, db, pool, session_id.clone(), host_id, route, cols, rows, command)
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

    #[allow(clippy::too_many_arguments)]
    async fn do_connect(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        pool: &ConnectionPool,
        session_id: String,
        host_id: Option<String>,
        route: Route,
        cols: u16,
        rows: u16,
        command: Option<String>,
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
        let progress = |step: u8, step_name: &str, message: &str| emit_progress(step, step_name, message, false);
        let fail = |step: u8, message: String| {
            emit_progress(step, "error", &message, true);
            message
        };

        // ── 1–3. Connection: through the jump hosts, verified and logged in.
        // An open connection to the same host is reused (no second login).
        let (mut connection, reused) = pool.connect(&db, &route, &progress).await.map_err(|e| fail(1, e))?;
        self.check_cancelled(&session_id).await?;

        // ── 4. Shell channel with a PTY.
        emit_progress(4, "opening_channel", "Opening shell channel...", false);
        let channel = match connection.open_session().await {
            Ok(channel) => channel,
            // A shared connection may be at the server's session limit (sshd
            // MaxSessions): log in again on a connection of its own.
            Err(russh::Error::ChannelOpenFailure(_)) if reused => {
                emit_progress(4, "opening_channel", "The open connection refused another shell; connecting separately...", false);
                connection = pool.connect_new(&db, &route, &progress).await.map_err(|e| fail(1, e))?;
                self.check_cancelled(&session_id).await?;
                connection
                    .open_session()
                    .await
                    .map_err(|e| fail(4, format!("Channel open failed: {e}")))?
            }
            Err(e) => return Err(fail(4, format!("Channel open failed: {e}"))),
        };

        let opened = async {
            channel
                .request_pty(true, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
                .await
                .map_err(|e| fail(4, format!("PTY request failed: {e}")))?;
            // A tab can run a command (e.g. `docker exec -it`) instead of the login shell.
            match &command {
                Some(command) => channel
                    .exec(true, command.as_str())
                    .await
                    .map_err(|e| fail(4, format!("Command request failed: {e}")))?,
                None => channel
                    .request_shell(true)
                    .await
                    .map_err(|e| fail(4, format!("Shell request failed: {e}")))?,
            }
            // Last checkpoint before registration: past this point the session is
            // live in the map, so a late cancel is handled by the connect() wrapper.
            self.check_cancelled(&session_id).await
        }
        .await;
        if let Err(e) = opened {
            // The connection may be shared: close just this channel.
            let _ = channel.close().await;
            return Err(e);
        }

        emit_progress(5, "ready", "Shell session ready.", false);

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SessionCommand>();

        let session = Arc::new(SshSession {
            id: session_id.clone(),
            connection,
            cmd_tx,
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
                            // The tab was closed: end this shell. The connection
                            // itself may still serve other tabs, SFTP or tunnels.
                            None => {
                                let _ = channel.close().await;
                                break;
                            }
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
        // Dropping the session ends its shell; the connection closes once
        // nothing else (another tab, SFTP, a tunnel) uses it.
        let removed = self.sessions.write().await.remove(session_id);
        if removed.is_none() && self.connecting.lock().await.contains(session_id) {
            // No registered session, but a connect is in flight for this id —
            // the tab was closed mid-connect. Mark it so do_connect aborts at
            // its next checkpoint (and so a session established in the gap
            // between checkpoints is caught by connect()'s final check).
            self.cancelled.lock().await.insert(session_id.to_string());
        }
        Ok(())
    }

    /// Ends every terminal session (app shutdown; the pool then says goodbye
    /// on the connections).
    pub async fn disconnect_all(&self) {
        self.sessions.write().await.clear();
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
    let Some(connection) = session.upgrade().map(|s| s.connection.clone()) else { return };
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        connection.exec("cat /etc/os-release", None, 8192),
    )
    .await;
    drop(connection);

    let Some(slug) = result.ok().and_then(Result::ok).and_then(|output| parse_os_release(&output.stdout_text())) else {
        return;
    };
    if let Ok(()) = db.update_host_os_icon(&host_id, &slug) {
        let _ = app.emit(
            "host-os-detected",
            serde_json::json!({ "host_id": host_id, "os_icon": slug }),
        );
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
