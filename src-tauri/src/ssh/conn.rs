//! Authenticated SSH connections, and the routes to them through jump hosts.
//!
//! A host can sit behind a chain of jump hosts: its jump host, that host's
//! own jump host, and so on. A [`Route`] lists them outermost first, then the
//! host itself; each hop is reached through a `direct-tcpip` channel of the
//! one before it.
//!
//! Connections are shared like OpenSSH's ControlMaster: terminal tabs, SFTP,
//! tunnels, remote desktops behind a bastion and the exec helpers all open
//! channels on one authenticated connection per host, so a password, key
//! passphrase or 2FA code is asked once per connection instead of once per
//! tab. A connection closes when the last thing using it lets go of its
//! `Arc`; the jump hosts it rides on stay up as long as it does.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use russh::client::{self, Handle, Msg};
use russh::{Channel, ChannelMsg, Disconnect};
use tokio::sync::{mpsc, Mutex, RwLock};

use super::{authenticate, client_config_for, configure_tcp_stream, ForwardedTcpip, SshAuth, SshClientHandler, SshStream};
use crate::db::Database;

/// Longest chain of jump hosts in front of a host (also ends loops).
pub const MAX_JUMP_HOPS: usize = 8;

/// How long a disconnect may take when the app shuts down.
const SHUTDOWN_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// One login on the way to a host.
#[derive(Clone)]
pub struct Hop {
    /// Identifies a connection that can be shared: the host, its config
    /// version and the route in front of it. `None` is never shared.
    pub key: Option<String>,
    pub address: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    /// The host's 2FA secret: one-time-code prompts are answered with it.
    pub totp: Option<super::totp::Totp>,
}

impl Hop {
    /// "user@address" (with ":port" when it isn't 22).
    pub fn target(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.username, self.address)
        } else {
            format!("{}@{}:{}", self.username, self.address, self.port)
        }
    }
}

/// Jump hosts, outermost first, then the host itself.
pub type Route = Vec<Hop>;

/// Connection progress for the UI: (step, step name, message). Steps follow
/// [`super::SshProgressPayload`]: 1 connect, 2 host key, 3 auth.
pub type Progress<'a> = &'a (dyn Fn(u8, &str, &str) + Sync);

/// Channels the server opens for remote forwards (`ssh -R`), routed to the
/// tunnel that asked for that listen address and port.
#[derive(Default)]
pub struct ForwardRouter {
    routes: std::sync::Mutex<HashMap<(String, u32), mpsc::UnboundedSender<ForwardedTcpip>>>,
}

impl ForwardRouter {
    /// The tunnel for `address:port`. Servers report the address as it was
    /// requested, but when only one tunnel uses the port it gets the
    /// connection whatever the spelling.
    pub fn sender(&self, address: &str, port: u32) -> Option<mpsc::UnboundedSender<ForwardedTcpip>> {
        let routes = self.routes.lock().ok()?;
        if let Some(tx) = routes.get(&(address.to_string(), port)) {
            return Some(tx.clone());
        }
        let mut on_port = routes.iter().filter(|((_, p), _)| *p == port);
        match (on_port.next(), on_port.next()) {
            (Some((_, tx)), None) => Some(tx.clone()),
            _ => None,
        }
    }

    fn insert(&self, address: &str, port: u32, tx: mpsc::UnboundedSender<ForwardedTcpip>) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.insert((address.to_string(), port), tx);
        }
    }

    fn remove(&self, address: &str, port: u32) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.remove(&(address.to_string(), port));
        }
    }
}

/// What a command printed and how it ended.
#[derive(Debug, Default)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
}

impl ExecOutput {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

pub struct SshConnection {
    /// "user@address", for messages.
    pub target: String,
    /// In an `Arc` so a dropped connection can still say goodbye from a task.
    /// Opening channels needs `&Handle`; requests that wait for a reply
    /// (remote forwards) need `&mut Handle`.
    handle: Arc<RwLock<Handle<SshClientHandler>>>,
    /// The jump host connection this one is tunneled through.
    via: Option<Arc<SshConnection>>,
    forwards: Arc<ForwardRouter>,
}

impl SshConnection {
    pub async fn open_session(&self) -> Result<Channel<Msg>, russh::Error> {
        self.handle.read().await.channel_open_session().await
    }

    pub async fn open_direct_tcpip(
        &self,
        host: &str,
        port: u16,
        originator_address: &str,
        originator_port: u16,
    ) -> Result<Channel<Msg>, russh::Error> {
        self.handle
            .read()
            .await
            .channel_open_direct_tcpip(host, port as u32, originator_address, originator_port as u32)
            .await
    }

    /// Ask the server to listen on `host:port` (`ssh -R`). Returns the port it
    /// listens on and the connections it accepts there.
    pub async fn tcpip_forward(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(u32, mpsc::UnboundedReceiver<ForwardedTcpip>), russh::Error> {
        let (tx, rx) = mpsc::unbounded_channel();
        // Routed before asking: a client may connect as soon as it listens.
        self.forwards.insert(host, port as u32, tx.clone());
        match self.handle.write().await.tcpip_forward(host, port as u32).await {
            Ok(bound) => {
                // The reply only carries a port when the server picked one.
                let bound = if bound == 0 { port as u32 } else { bound };
                if bound != port as u32 {
                    self.forwards.remove(host, port as u32);
                    self.forwards.insert(host, bound, tx);
                }
                Ok((bound, rx))
            }
            Err(e) => {
                self.forwards.remove(host, port as u32);
                Err(e)
            }
        }
    }

    pub async fn cancel_tcpip_forward(&self, host: &str, port: u32) {
        self.forwards.remove(host, port);
        let _ = self.handle.read().await.cancel_tcpip_forward(host, port).await;
    }

    /// How many jump hosts it goes through.
    fn depth(&self) -> usize {
        self.via.as_ref().map_or(0, |via| via.depth() + 1)
    }

    /// Whether this connection, or one it rides on, has ended.
    pub fn is_closed(&self) -> bool {
        self.handle.try_read().is_ok_and(|handle| handle.is_closed())
            || self.via.as_ref().is_some_and(|via| via.is_closed())
    }

    /// Run `command` on its own channel. `stdin` is sent and closed first; the
    /// output is capped at `max_output` bytes per stream. Callers bound the
    /// time it may take.
    pub async fn exec(&self, command: &str, stdin: Option<&[u8]>, max_output: usize) -> Result<ExecOutput, String> {
        let mut channel = self.open_session().await.map_err(|e| match e {
            russh::Error::ChannelOpenFailure(_) => format!(
                "The server refused another session on the connection to {} (sshd MaxSessions). \
                 Close a tab to this host, or turn off connection sharing in Settings > SSH & Sessions.",
                self.target
            ),
            e => format!("Could not open a channel: {e}"),
        })?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| format!("Could not run the command: {e}"))?;
        if let Some(input) = stdin {
            channel
                .data(input)
                .await
                .map_err(|e| format!("Could not send input: {e}"))?;
        }
        channel.eof().await.map_err(|e| format!("Could not send input: {e}"))?;

        let mut output = ExecOutput::default();
        let mut truncated = false;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => append_capped(&mut output.stdout, &data, max_output, &mut truncated),
                ChannelMsg::ExtendedData { data, .. } => {
                    append_capped(&mut output.stderr, &data, max_output, &mut truncated)
                }
                ChannelMsg::ExitStatus { exit_status } => output.exit_status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
            if truncated {
                break;
            }
        }
        // Normally the server has closed it already when the command exited.
        let _ = channel.close().await;
        Ok(output)
    }

    async fn disconnect(&self) {
        let _ = self
            .handle
            .read()
            .await
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
    }
}

fn append_capped(buffer: &mut Vec<u8>, data: &[u8], max: usize, truncated: &mut bool) {
    let room = max.saturating_sub(buffer.len());
    buffer.extend_from_slice(&data[..data.len().min(room)]);
    if data.len() > room {
        *truncated = true;
    }
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        let handle = self.handle.clone();
        // The jump host stays up until this connection has said goodbye
        // through it.
        let via = self.via.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = handle.read().await.disconnect(Disconnect::ByApplication, "", "en").await;
                drop(via);
            });
        }
    }
}

/// Live connections by [`Hop::key`].
pub struct ConnectionPool {
    live: std::sync::Mutex<HashMap<String, Weak<SshConnection>>>,
    /// One login per key at a time: whoever comes second waits and reuses it.
    logins: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    sharing: AtomicBool,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        ConnectionPool {
            live: std::sync::Mutex::new(HashMap::new()),
            logins: Mutex::new(HashMap::new()),
            sharing: AtomicBool::new(true),
        }
    }

    /// Turn connection sharing on or off (Settings). Off, every connect logs
    /// in on a connection of its own, jump hosts included.
    pub fn set_sharing(&self, enabled: bool) {
        self.sharing.store(enabled, Ordering::Relaxed);
    }

    /// Connect along `route`, reusing live connections. Returns the
    /// connection to the last hop and whether it was already open.
    pub async fn connect(
        &self,
        db: &Arc<Database>,
        route: &[Hop],
        progress: Progress<'_>,
    ) -> Result<(Arc<SshConnection>, bool), String> {
        self.connect_route(db, route, progress, true).await
    }

    /// Like [`Self::connect`], but the last hop gets a new connection (its
    /// jump hosts are still shared). For when a shared connection refuses
    /// another channel, e.g. at sshd's `MaxSessions`.
    pub async fn connect_new(
        &self,
        db: &Arc<Database>,
        route: &[Hop],
        progress: Progress<'_>,
    ) -> Result<Arc<SshConnection>, String> {
        self.connect_route(db, route, progress, false).await.map(|(connection, _)| connection)
    }

    async fn connect_route(
        &self,
        db: &Arc<Database>,
        route: &[Hop],
        progress: Progress<'_>,
        reuse_last: bool,
    ) -> Result<(Arc<SshConnection>, bool), String> {
        if route.is_empty() {
            return Err("Nothing to connect to".to_string());
        }
        if route.len() > MAX_JUMP_HOPS + 1 {
            return Err(format!("More than {MAX_JUMP_HOPS} jump hosts in a row"));
        }
        let sharing = self.sharing.load(Ordering::Relaxed);
        let shareable = |index: usize| sharing && route[index].key.is_some() && (reuse_last || index + 1 < route.len());

        // Start after the last hop that is already connected: its jump hosts
        // are, too.
        let mut start = 0;
        let mut via: Option<Arc<SshConnection>> = None;
        for index in (0..route.len()).rev() {
            if !shareable(index) {
                continue;
            }
            if let Some(live) = self.live_connection(route[index].key.as_deref().unwrap_or_default()) {
                progress(1, "connecting", &format!("Reusing the open connection to {}", describe(route, index)));
                via = Some(live);
                start = index + 1;
                break;
            }
        }
        let mut reused = start == route.len();
        for index in start..route.len() {
            let (connection, was_live) = self.hop(db, route, index, via.take(), shareable(index), progress).await?;
            reused = was_live;
            via = Some(connection);
        }
        let connection = via.ok_or_else(|| "Nothing to connect to".to_string())?;
        Ok((connection, reused))
    }

    async fn hop(
        &self,
        db: &Arc<Database>,
        route: &[Hop],
        index: usize,
        via: Option<Arc<SshConnection>>,
        shareable: bool,
        progress: Progress<'_>,
    ) -> Result<(Arc<SshConnection>, bool), String> {
        let key = match (&route[index].key, shareable) {
            (Some(key), true) => key.clone(),
            _ => return Ok((Arc::new(open(db, route, index, via, progress).await?), false)),
        };
        let gate = self.logins.lock().await.entry(key.clone()).or_default().clone();
        let _login = gate.lock().await;
        if let Some(live) = self.live_connection(&key) {
            progress(1, "connecting", &format!("Reusing the open connection to {}", describe(route, index)));
            return Ok((live, true));
        }
        let connection = Arc::new(open(db, route, index, via, progress).await?);
        if let Ok(mut live) = self.live.lock() {
            live.insert(key, Arc::downgrade(&connection));
        }
        Ok((connection, false))
    }

    fn live_connection(&self, key: &str) -> Option<Arc<SshConnection>> {
        let mut live = self.live.lock().ok()?;
        live.retain(|_, connection| connection.strong_count() > 0);
        live.get(key).and_then(Weak::upgrade).filter(|connection| !connection.is_closed())
    }

    /// Say goodbye on every open connection (app shutdown).
    pub async fn disconnect_all(&self) {
        let mut connections: Vec<Arc<SshConnection>> = match self.live.lock() {
            Ok(live) => live.values().filter_map(Weak::upgrade).collect(),
            Err(_) => return,
        };
        // Innermost first, so a host's goodbye still gets through its jump host.
        connections.sort_by_key(|connection| std::cmp::Reverse(connection.depth()));
        for connection in &connections {
            let _ = tokio::time::timeout(SHUTDOWN_DISCONNECT_TIMEOUT, connection.disconnect()).await;
        }
    }
}

/// "the jump host ops@bastion" / "root@10.0.0.5", for progress messages.
fn describe(route: &[Hop], index: usize) -> String {
    let hop = &route[index];
    if index + 1 == route.len() {
        hop.target()
    } else if route.len() > 2 {
        format!("jump host {}/{} {}", index + 1, route.len() - 1, hop.target())
    } else {
        format!("jump host {}", hop.target())
    }
}

/// Log in to `route[index]`, directly or through `via`.
async fn open(
    db: &Arc<Database>,
    route: &[Hop],
    index: usize,
    via: Option<Arc<SshConnection>>,
    progress: Progress<'_>,
) -> Result<SshConnection, String> {
    let hop = &route[index];
    let name = describe(route, index);
    let is_jump = index + 1 < route.len();
    // Errors name the jump host they come from; the target's speak for themselves.
    let context = |e: String| if is_jump { format!("Jump host {}: {e}", hop.target()) } else { e };

    progress(1, "connecting", &format!("Connecting to {name}..."));
    let stream = match &via {
        Some(via) => {
            let channel = via
                .open_direct_tcpip(&hop.address, hop.port, "127.0.0.1", 0)
                .await
                .map_err(|e| context(format!("could not reach {}:{} through {}: {e}", hop.address, hop.port, via.target)))?;
            SshStream::Tunneled(channel.into_stream())
        }
        None => {
            let tcp = tokio::net::TcpStream::connect((hop.address.as_str(), hop.port))
                .await
                .map_err(|e| context(format!("Connection to {}:{} failed: {e}", hop.address, hop.port)))?;
            configure_tcp_stream(&tcp);
            SshStream::Direct(tcp)
        }
    };

    progress(2, "host_key", &format!("Verifying the host key of {name} (Trust On First Use)..."));
    let forwards = Arc::new(ForwardRouter::default());
    let handler = SshClientHandler {
        address: hop.address.clone(),
        port: hop.port,
        db: db.clone(),
        forwards: forwards.clone(),
    };
    let mut handle = client::connect_stream(client_config_for(db, &hop.address, hop.port), stream, handler)
        .await
        .map_err(|e| context(format!("SSH connection failed: {e}")))?;

    progress(3, "authenticating", &format!("Authenticating to {name}..."));
    let prompt_target = if is_jump { format!("{} (jump host)", hop.target()) } else { hop.target() };
    match authenticate(&mut handle, &hop.username, &hop.auth, hop.totp.as_ref(), &prompt_target).await {
        Ok(true) => {}
        Ok(false) => return Err(context("Authentication rejected by server".to_string())),
        Err(e) => return Err(context(e)),
    }

    Ok(SshConnection {
        target: hop.target(),
        handle: Arc::new(RwLock::new(handle)),
        via,
        forwards,
    })
}

/// Adds the public key read from stdin to `~/.ssh/authorized_keys` unless it
/// is there already (same key data, any comment), like `ssh-copy-id`: new
/// files get private permissions, a last line without a newline is ended
/// first, and SELinux labels are restored where that applies. Prints
/// "already" or "added". POSIX sh, wrapped so any login shell can run it.
pub const INSTALL_PUBLIC_KEY_SCRIPT: &str = r#"umask 077
key=$(cat)
data=$(printf "%s" "$key" | awk "{print \$2}")
[ -n "$data" ] || { echo "not a public key" >&2; exit 2; }
mkdir -p "$HOME/.ssh" || exit 1
f="$HOME/.ssh/authorized_keys"
touch "$f" || exit 1
if grep -qF "$data" "$f"; then echo already; exit 0; fi
if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi
printf "%s\n" "$key" >> "$f" || exit 1
command -v restorecon >/dev/null 2>&1 && restorecon -F "$HOME/.ssh" "$f" >/dev/null 2>&1
echo added"#;

/// The shell command running `script` with `sh`, whatever the login shell.
/// Lines are joined with `;`: csh and tcsh reject a newline inside quotes.
/// (Every line of the scripts here is a complete command.)
pub fn sh_command(script: &str) -> String {
    let one_line = script.lines().map(str::trim).filter(|line| !line.is_empty()).collect::<Vec<_>>().join("; ");
    format!("sh -c '{}'", one_line.replace('\'', "'\\''"))
}

/// A byte stream to `address:port`, through the end of `jump_route` when it
/// isn't empty (VNC and RDP behind a bastion). The connection returned with
/// it must stay alive while the stream is in use.
pub async fn open_stream(
    pool: &ConnectionPool,
    db: &Arc<Database>,
    jump_route: &[Hop],
    address: &str,
    port: u16,
    progress: Progress<'_>,
) -> Result<(SshStream, Option<Arc<SshConnection>>), String> {
    if jump_route.is_empty() {
        let tcp = tokio::net::TcpStream::connect((address, port))
            .await
            .map_err(|e| format!("Connection to {address}:{port} failed: {e}"))?;
        configure_tcp_stream(&tcp);
        return Ok((SshStream::Direct(tcp), None));
    }
    let (jump, _) = pool.connect(db, jump_route, progress).await?;
    let channel = jump
        .open_direct_tcpip(address, port, "127.0.0.1", 0)
        .await
        .map_err(|e| format!("Could not reach {address}:{port} through jump host {}: {e}", jump.target))?;
    Ok((SshStream::Tunneled(channel.into_stream()), Some(jump)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_forwards_route_by_address_and_port() {
        let router = ForwardRouter::default();
        let (local_tx, _local_rx) = mpsc::unbounded_channel();
        let (public_tx, _public_rx) = mpsc::unbounded_channel();
        router.insert("127.0.0.1", 8080, local_tx.clone());
        // Only one tunnel on the port: any spelling of the address finds it.
        assert!(router.sender("localhost", 8080).is_some_and(|tx| tx.same_channel(&local_tx)));
        // Two on the same port: each by its own address, nothing for others.
        router.insert("0.0.0.0", 8080, public_tx.clone());
        assert!(router.sender("0.0.0.0", 8080).is_some_and(|tx| tx.same_channel(&public_tx)));
        assert!(router.sender("127.0.0.1", 8080).is_some_and(|tx| tx.same_channel(&local_tx)));
        assert!(router.sender("localhost", 8080).is_none());
        // Stopping one leaves the other.
        router.remove("0.0.0.0", 8080);
        assert!(router.sender("0.0.0.0", 8080).is_some_and(|tx| tx.same_channel(&local_tx)));
        assert!(router.sender("127.0.0.1", 9090).is_none());
    }

    #[test]
    fn scripts_become_one_line_for_any_login_shell() {
        let command = sh_command("umask 077\n  echo \"a b\"\n\nexit 0\n");
        assert_eq!(command, "sh -c 'umask 077; echo \"a b\"; exit 0'");
        assert_eq!(sh_command("echo 'quoted'"), "sh -c 'echo '\\''quoted'\\'''");
        // Joining lines is only safe when no quoted string spans two lines.
        for line in INSTALL_PUBLIC_KEY_SCRIPT.lines() {
            assert_eq!(line.matches('"').count() % 2, 0, "quote spans lines at: {line}");
        }
        assert!(!sh_command(INSTALL_PUBLIC_KEY_SCRIPT).contains('\n'));
    }
}
