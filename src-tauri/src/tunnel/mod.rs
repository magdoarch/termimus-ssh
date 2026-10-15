//! SSH port forwarding: local (`ssh -L`), remote (`ssh -R`) and dynamic SOCKS
//! (`ssh -D`). Each running rule owns one SSH connection, made through the
//! host's jump host when one is configured.

mod socks;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg, ChannelOpenFailure, Disconnect};
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::db::models::PortForwardRule;
use crate::db::Database;
use crate::ssh::{ForwardedTcpip, JumpHostConfig, SshAuth, SshClientHandler};

/// How often a running tunnel checks whether its SSH connection is gone.
const CONNECTION_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// A SOCKS client must finish its handshake within this time.
const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Remote forward: connecting to the local target must succeed within this time.
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause after a failed accept() (e.g. out of file descriptors) before retrying.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(200);
/// Upper bound for asking the server to stop listening on shutdown.
const CANCEL_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a finished connection waits for the server to close its channel
/// before closing it from our side.
const CHANNEL_CLOSE_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into().trim().to_string(),
            port,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// What a rule does. Stored rules keep the client-side endpoint in
/// `local_*` and the server-side endpoint in `remote_*` for every type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelSpec {
    /// `ssh -L`: listen on this machine, connect to `target` from the server.
    Local { listen: Endpoint, target: Endpoint },
    /// `ssh -R`: the server listens on `listen`, connections come back here
    /// and go to `target` as reached from this machine.
    Remote { listen: Endpoint, target: Endpoint },
    /// `ssh -D`: a SOCKS4/5 proxy on this machine; each connection goes
    /// wherever the client asks, reached from the server.
    Dynamic { listen: Endpoint },
}

impl TunnelSpec {
    pub fn from_rule(rule: &PortForwardRule) -> Result<Self, String> {
        let local = Endpoint::new(&rule.local_address, rule.local_port);
        let remote = Endpoint::new(&rule.remote_address, rule.remote_port);
        let with_default_host = |mut endpoint: Endpoint| {
            if endpoint.host.is_empty() {
                endpoint.host = "127.0.0.1".to_string();
            }
            endpoint
        };
        let spec = match rule.forward_type.as_str() {
            "local" => TunnelSpec::Local {
                listen: with_default_host(local),
                target: remote,
            },
            "remote" => TunnelSpec::Remote {
                listen: with_default_host(remote),
                target: local,
            },
            "dynamic" => TunnelSpec::Dynamic {
                listen: with_default_host(local),
            },
            other => return Err(format!("Unknown port forwarding type '{other}'")),
        };
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        let (listen, target) = match self {
            TunnelSpec::Local { listen, target } | TunnelSpec::Remote { listen, target } => (listen, Some(target)),
            TunnelSpec::Dynamic { listen } => (listen, None),
        };
        if listen.port == 0 {
            return Err("Listen port must be between 1 and 65535".to_string());
        }
        if let Some(target) = target {
            if target.host.is_empty() {
                return Err("Destination host is required".to_string());
            }
            if target.port == 0 {
                return Err("Destination port must be between 1 and 65535".to_string());
            }
        }
        Ok(())
    }
}

/// The SSH server a tunnel runs through.
pub struct SshTarget {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub jump: Option<JumpHostConfig>,
}

/// Emitted when a tunnel starts and when it stops (by request or on its own).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    pub rule_id: String,
    /// "started" or "stopped".
    pub state: &'static str,
    /// Why the tunnel stopped on its own; `None` when stopped by the user.
    pub error: Option<String>,
}

pub type StatusSink = Arc<dyn Fn(TunnelStatus) + Send + Sync>;

pub struct ActiveTunnel {
    /// Distinguishes this run from a later restart of the same rule, so a
    /// finishing task only removes its own entry.
    generation: u64,
    /// `None` while the SSH connection is still being established.
    stop_tx: Option<oneshot::Sender<()>>,
}

/// How a running tunnel receives connections.
enum Intake {
    /// Local and dynamic forwards: a listener on this machine.
    Listener(TcpListener),
    /// Remote forwards: channels the server opens for its listening port.
    Remote {
        forwarded: mpsc::UnboundedReceiver<ForwardedTcpip>,
        /// Port the server actually listens on.
        bound_port: u32,
    },
}

pub struct TunnelManager {
    active: Arc<Mutex<HashMap<String, ActiveTunnel>>>,
    next_generation: AtomicU64,
}

impl TunnelManager {
    pub fn new() -> Self {
        TunnelManager {
            active: Arc::new(Mutex::new(HashMap::new())),
            next_generation: AtomicU64::new(1),
        }
    }

    pub async fn list_active(&self) -> Vec<String> {
        self.active
            .lock()
            .await
            .iter()
            .filter(|(_, t)| t.stop_tx.is_some())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Connect and start forwarding. Returns once the tunnel is listening
    /// (locally, or on the server for remote forwards); later state changes
    /// are reported through `status`.
    pub async fn start(
        &self,
        db: Arc<Database>,
        rule_id: String,
        ssh: SshTarget,
        spec: TunnelSpec,
        status: StatusSink,
    ) -> Result<(), String> {
        spec.validate()?;

        // Reserve the rule before the (slow) connect so two concurrent starts
        // can't both get past this check.
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        {
            let mut active = self.active.lock().await;
            if active.contains_key(&rule_id) {
                return Err("Tunnel is already running".to_string());
            }
            active.insert(rule_id.clone(), ActiveTunnel { generation, stop_tx: None });
        }

        let (handle, jump_handle, intake) = match setup(db, &ssh, &spec).await {
            Ok(v) => v,
            Err(e) => {
                remove_if_current(&self.active, &rule_id, generation).await;
                return Err(e);
            }
        };
        let handle = Arc::new(handle);

        // Publish the stop handle before the task can possibly finish and
        // remove the entry. If the rule was stopped while connecting, bail out.
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let published = match self.active.lock().await.get_mut(&rule_id) {
            Some(t) if t.generation == generation => {
                t.stop_tx = Some(stop_tx);
                true
            }
            _ => false,
        };
        if !published {
            disconnect_quietly(&handle, jump_handle.as_ref()).await;
            return Err("Tunnel was stopped while connecting".to_string());
        }

        let active = self.active.clone();
        tokio::spawn(async move {
            status(TunnelStatus {
                rule_id: rule_id.clone(),
                state: "started",
                error: None,
            });
            let error = serve(&handle, jump_handle.as_ref(), intake, &spec, stop_rx).await;
            if let Some(e) = &error {
                eprintln!("Tunnel {rule_id} stopped: {e}");
            }
            // Whatever ended it, tear the connection down and forget the rule
            // so it can be started again.
            disconnect_quietly(&handle, jump_handle.as_ref()).await;
            remove_if_current(&active, &rule_id, generation).await;
            status(TunnelStatus {
                rule_id,
                state: "stopped",
                error,
            });
        });

        Ok(())
    }

    pub async fn stop(&self, rule_id: &str) -> Result<(), String> {
        let mut active = self.active.lock().await;
        // Removing a still-connecting entry makes start() abort.
        if let Some(tunnel) = active.remove(rule_id) {
            if let Some(stop_tx) = tunnel.stop_tx {
                let _ = stop_tx.send(());
            }
        }
        Ok(())
    }
}

/// Connect and start listening (locally, or on the server for `-R`).
async fn setup(
    db: Arc<Database>,
    ssh: &SshTarget,
    spec: &TunnelSpec,
) -> Result<(Handle<SshClientHandler>, Option<Handle<SshClientHandler>>, Intake), String> {
    let (forwarded_tx, forwarded_rx) = match spec {
        TunnelSpec::Remote { .. } => {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        }
        _ => (None, None),
    };
    let (mut handle, jump_handle) = crate::ssh::connect_authenticated_with_forwarding(
        db,
        &ssh.address,
        ssh.port,
        &ssh.username,
        &ssh.auth,
        ssh.jump.as_ref(),
        forwarded_tx,
    )
    .await
    .map_err(|e| format!("Tunnel: {e}"))?;

    let intake = match spec {
        TunnelSpec::Local { listen, .. } | TunnelSpec::Dynamic { listen } => {
            TcpListener::bind((listen.host.as_str(), listen.port))
                .await
                .map(Intake::Listener)
                .map_err(|e| format!("Failed to listen on {listen}: {e}"))
        }
        TunnelSpec::Remote { listen, .. } => match handle.tcpip_forward(listen.host.clone(), listen.port as u32).await {
            // The reply only carries a port when the server picked one.
            Ok(port) => Ok(Intake::Remote {
                forwarded: forwarded_rx.expect("created for remote forwards"),
                bound_port: if port == 0 { listen.port as u32 } else { port },
            }),
            Err(russh::Error::RequestDenied) => Err(format!(
                "The SSH server refused to listen on {listen}: the port may already be in use on the server, \
                 or remote forwarding is disabled (AllowTcpForwarding in sshd_config). Binding to a \
                 non-loopback address also needs GatewayPorts."
            )),
            Err(e) => Err(format!("Remote forward request failed: {e}")),
        },
    };
    match intake {
        Ok(intake) => Ok((handle, jump_handle, intake)),
        Err(e) => {
            disconnect_quietly(&handle, jump_handle.as_ref()).await;
            Err(e)
        }
    }
}

/// Accept connections until stopped. Returns why the tunnel ended on its own
/// (`None` when stopped by the user).
async fn serve(
    handle: &Arc<Handle<SshClientHandler>>,
    jump_handle: Option<&Handle<SshClientHandler>>,
    intake: Intake,
    spec: &TunnelSpec,
    mut stop_rx: oneshot::Receiver<()>,
) -> Option<String> {
    let mut connection_check = tokio::time::interval(CONNECTION_CHECK_INTERVAL);
    let connection_lost = || handle.is_closed() || jump_handle.is_some_and(|j| j.is_closed());

    match intake {
        Intake::Listener(listener) => loop {
            tokio::select! {
                _ = &mut stop_rx => return None,
                _ = connection_check.tick() => {
                    if connection_lost() {
                        return Some("SSH connection closed".to_string());
                    }
                }
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let handle = handle.clone();
                        let spec = spec.clone();
                        tokio::spawn(async move {
                            let result = match &spec {
                                TunnelSpec::Local { target, .. } => forward_local(&handle, stream, peer, target).await,
                                TunnelSpec::Dynamic { .. } => forward_socks(&handle, stream, peer).await,
                                TunnelSpec::Remote { .. } => Ok(()),
                            };
                            if let Err(e) = result {
                                eprintln!("Tunnel connection from {peer}: {e}");
                            }
                        });
                    }
                    // Usually transient (e.g. too many open files): keep serving.
                    Err(e) => {
                        eprintln!("Tunnel accept error: {e}");
                        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                    }
                },
            }
        },
        Intake::Remote { mut forwarded, bound_port } => {
            let TunnelSpec::Remote { listen, target } = spec else {
                return Some("Internal error: remote intake without a remote rule".to_string());
            };
            let reason = loop {
                tokio::select! {
                    _ = &mut stop_rx => break None,
                    _ = connection_check.tick() => {
                        if connection_lost() {
                            break Some("SSH connection closed".to_string());
                        }
                    }
                    incoming = forwarded.recv() => match incoming {
                        Some(incoming) => {
                            let target = target.clone();
                            tokio::spawn(async move {
                                let origin = format!("{}:{}", incoming.originator_address, incoming.originator_port);
                                if let Err(e) = forward_remote(incoming, &target, bound_port).await {
                                    eprintln!("Remote-forwarded connection from {origin}: {e}");
                                }
                            });
                        }
                        // The connection (and with it the handler) is gone.
                        None => break Some("SSH connection closed".to_string()),
                    },
                }
            };
            // Ask the server to stop listening; the disconnect that follows
            // would end it anyway, so don't wait long.
            let _ = tokio::time::timeout(
                CANCEL_FORWARD_TIMEOUT,
                handle.cancel_tcpip_forward(listen.host.clone(), bound_port),
            )
            .await;
            reason
        }
    }
}

/// `-L`: open a direct-tcpip channel to the fixed target.
async fn forward_local(
    handle: &Handle<SshClientHandler>,
    stream: TcpStream,
    peer: SocketAddr,
    target: &Endpoint,
) -> Result<(), String> {
    let channel = handle
        .channel_open_direct_tcpip(target.host.clone(), target.port as u32, peer.ip().to_string(), peer.port() as u32)
        .await
        .map_err(|e| format!("could not open a channel to {target}: {e}"))?;
    pipe(channel, stream).await;
    Ok(())
}

/// `-D`: read the SOCKS request, then open a channel to whatever it asks for.
async fn forward_socks(handle: &Handle<SshClientHandler>, mut stream: TcpStream, peer: SocketAddr) -> Result<(), String> {
    let request = match tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, socks::read_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(e)) => return Err(format!("SOCKS handshake failed: {e}")),
        Err(_) => return Err("SOCKS handshake timed out".to_string()),
    };
    match handle
        .channel_open_direct_tcpip(request.host.clone(), request.port as u32, peer.ip().to_string(), peer.port() as u32)
        .await
    {
        Ok(channel) => {
            socks::send_success(&mut stream, request.version)
                .await
                .map_err(|e| format!("SOCKS reply failed: {e}"))?;
            pipe(channel, stream).await;
            Ok(())
        }
        Err(e) => {
            let _ = socks::send_failure(&mut stream, request.version, connect_failure(&e)).await;
            Err(format!("connect to {}:{} through the server failed: {e}", request.host, request.port))
        }
    }
}

fn connect_failure(e: &russh::Error) -> socks::ConnectFailure {
    match e {
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => {
            socks::ConnectFailure::NotAllowed
        }
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed) => socks::ConnectFailure::Refused,
        _ => socks::ConnectFailure::General,
    }
}

/// `-R`: the server accepted a connection on our forwarded port; connect it
/// to the local target.
async fn forward_remote(incoming: ForwardedTcpip, target: &Endpoint, bound_port: u32) -> Result<(), String> {
    if incoming.connected_port != bound_port {
        let _ = incoming.channel.close().await;
        return Err(format!(
            "server opened a channel for port {} which this tunnel didn't request",
            incoming.connected_port
        ));
    }
    let stream = match tokio::time::timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let _ = incoming.channel.close().await;
            return Err(format!("could not connect to {target}: {e}"));
        }
        Err(_) => {
            let _ = incoming.channel.close().await;
            return Err(format!("connecting to {target} timed out"));
        }
    };
    pipe(incoming.channel, stream).await;
    Ok(())
}

/// Copy data both ways until both sides are done, propagating half-closes:
/// EOF from the TCP side becomes channel EOF and vice versa, so protocols
/// that finish sending before reading the reply keep working.
async fn pipe(mut channel: Channel<Msg>, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.split();
    let mut buf = vec![0u8; 32 * 1024];
    let mut local_eof = false;
    let mut remote_eof = false;
    let mut closed_by_server = false;

    loop {
        tokio::select! {
            read = reader.read(&mut buf), if !local_eof => match read {
                Ok(0) => {
                    local_eof = true;
                    let _ = channel.eof().await;
                    if remote_eof {
                        break;
                    }
                }
                Ok(n) => {
                    if channel.data(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { ref data }) => {
                    if writer.write_all(data).await.is_err() {
                        break;
                    }
                }
                Some(ChannelMsg::Eof) => {
                    remote_eof = true;
                    let _ = writer.shutdown().await;
                    if local_eof {
                        break;
                    }
                }
                Some(ChannelMsg::Close) | None => {
                    closed_by_server = true;
                    break;
                }
                _ => {}
            },
        }
    }
    if closed_by_server {
        return;
    }

    // Let the server send CLOSE (russh answers it) instead of closing first:
    // if we CLOSE while the server is still acknowledging our data, its late
    // WINDOW_ADJUST made russh before 0.54 fail with WrongChannel and drop the
    // whole SSH connection. The server never sends anything after its CLOSE.
    if !local_eof {
        let _ = channel.eof().await;
    }
    let server_closed = tokio::time::timeout(CHANNEL_CLOSE_GRACE, async {
        // Late data is discarded: the local side is done.
        while !matches!(channel.wait().await, Some(ChannelMsg::Close) | None) {}
    })
    .await
    .is_ok();
    if !server_closed {
        let _ = channel.close().await;
    }
}

async fn remove_if_current(active: &Mutex<HashMap<String, ActiveTunnel>>, rule_id: &str, generation: u64) {
    let mut active = active.lock().await;
    if active.get(rule_id).is_some_and(|t| t.generation == generation) {
        active.remove(rule_id);
    }
}

async fn disconnect_quietly(handle: &Handle<SshClientHandler>, jump_handle: Option<&Handle<SshClientHandler>>) {
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    if let Some(jump) = jump_handle {
        let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(forward_type: &str, local: (&str, u16), remote: (&str, u16)) -> PortForwardRule {
        PortForwardRule {
            id: "r".into(),
            host_id: "h".into(),
            label: "test".into(),
            forward_type: forward_type.into(),
            local_address: local.0.into(),
            local_port: local.1,
            remote_address: remote.0.into(),
            remote_port: remote.1,
            created_at: String::new(),
        }
    }

    #[test]
    fn spec_from_rule_maps_endpoints_per_type() {
        assert_eq!(
            TunnelSpec::from_rule(&rule("local", ("127.0.0.1", 8080), ("db", 5432))).unwrap(),
            TunnelSpec::Local { listen: Endpoint::new("127.0.0.1", 8080), target: Endpoint::new("db", 5432) }
        );
        // -R: the server listens on the remote_* endpoint, traffic comes back to local_*.
        assert_eq!(
            TunnelSpec::from_rule(&rule("remote", ("127.0.0.1", 3000), ("", 9000))).unwrap(),
            TunnelSpec::Remote { listen: Endpoint::new("127.0.0.1", 9000), target: Endpoint::new("127.0.0.1", 3000) }
        );
        assert_eq!(
            TunnelSpec::from_rule(&rule("dynamic", ("", 1080), ("", 0))).unwrap(),
            TunnelSpec::Dynamic { listen: Endpoint::new("127.0.0.1", 1080) }
        );
    }

    #[test]
    fn spec_validation() {
        assert!(TunnelSpec::from_rule(&rule("local", ("127.0.0.1", 0), ("db", 5432))).is_err());
        assert!(TunnelSpec::from_rule(&rule("local", ("127.0.0.1", 8080), (" ", 5432))).is_err());
        assert!(TunnelSpec::from_rule(&rule("remote", ("127.0.0.1", 0), ("", 9000))).is_err());
        assert!(TunnelSpec::from_rule(&rule("bogus", ("127.0.0.1", 1), ("x", 1))).is_err());
    }

    // ── End-to-end against a real sshd ─────────────────────────────────────
    //
    // SSH_TEST_ADDR=127.0.0.1:2222 SSH_TEST_USER=root SSH_TEST_KEY=/path/to/key \
    //   cargo test -- --ignored tunnels_end_to_end
    //
    // The SSH server must be this machine (its -R listener is checked from here)
    // with AllowTcpForwarding enabled.

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    /// Echoes everything until the client half-closes, then closes.
    async fn spawn_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        port
    }

    async fn spawn_http_ok() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                        .await;
                });
            }
        });
        port
    }

    /// Send `msg`, half-close, and expect the full echo followed by EOF.
    async fn assert_echo_on(mut stream: TcpStream, msg: &[u8]) {
        stream.write_all(msg).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut echoed))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(echoed, msg);
    }

    async fn assert_echo(port: u16, msg: &[u8]) {
        assert_echo_on(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), msg).await;
    }

    async fn socks5_connect(proxy_port: u16, host: &str, port: u16) -> (TcpStream, u8) {
        let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0u8; 2];
        s.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        s.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await.unwrap();
        (s, reply[1])
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn tunnels_end_to_end() {
        let addr = std::env::var("SSH_TEST_ADDR").expect("SSH_TEST_ADDR");
        let (ssh_host, ssh_port) = addr.rsplit_once(':').expect("host:port");
        let ssh_port: u16 = ssh_port.parse().unwrap();
        let user = std::env::var("SSH_TEST_USER").expect("SSH_TEST_USER");
        let pem = std::fs::read_to_string(std::env::var("SSH_TEST_KEY").expect("SSH_TEST_KEY")).unwrap();
        let ssh = || SshTarget {
            address: ssh_host.to_string(),
            port: ssh_port,
            username: user.clone(),
            auth: SshAuth::PrivateKey { pem: pem.clone(), passphrase: None },
            jump: None,
        };

        let config_home = std::env::temp_dir().join(format!("termimus-tunnel-test-{}", std::process::id()));
        std::env::set_var("XDG_CONFIG_HOME", &config_home);
        let db = Arc::new(Database::new().unwrap());

        let events: Arc<std::sync::Mutex<Vec<TunnelStatus>>> = Default::default();
        let sink: StatusSink = {
            let events = events.clone();
            Arc::new(move |status| events.lock().unwrap().push(status))
        };
        let echo_port = spawn_echo_server().await;
        let manager = TunnelManager::new();

        // -L
        let local_port = free_port();
        let spec = TunnelSpec::Local {
            listen: Endpoint::new("127.0.0.1", local_port),
            target: Endpoint::new("127.0.0.1", echo_port),
        };
        manager.start(db.clone(), "L".into(), ssh(), spec, sink.clone()).await.unwrap();
        assert_echo(local_port, b"hello via -L").await;

        // -R: sshd listens on remote_port and sends connections back to us.
        let remote_port = free_port();
        let spec = TunnelSpec::Remote {
            listen: Endpoint::new("127.0.0.1", remote_port),
            target: Endpoint::new("127.0.0.1", echo_port),
        };
        manager.start(db.clone(), "R".into(), ssh(), spec, sink.clone()).await.unwrap();
        assert_echo(remote_port, b"hello via -R").await;
        // Large payload both ways.
        let big: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
        assert_echo(remote_port, &big).await;

        // -R on a port that is busy on the server fails with a clear error.
        let spec = TunnelSpec::Remote {
            listen: Endpoint::new("127.0.0.1", echo_port),
            target: Endpoint::new("127.0.0.1", echo_port),
        };
        let err = manager.start(db.clone(), "R-busy".into(), ssh(), spec, sink.clone()).await.unwrap_err();
        assert!(err.contains("refused to listen"), "{err}");
        assert!(!manager.list_active().await.contains(&"R-busy".to_string()));

        // -D: SOCKS5 with a host name resolved by the server, and SOCKS4a.
        let socks_port = free_port();
        let spec = TunnelSpec::Dynamic { listen: Endpoint::new("127.0.0.1", socks_port) };
        manager.start(db.clone(), "D".into(), ssh(), spec, sink.clone()).await.unwrap();
        let (stream, code) = socks5_connect(socks_port, "localhost", echo_port).await;
        assert_eq!(code, 0, "SOCKS5 CONNECT should succeed");
        assert_echo_on(stream, b"hello via -D (socks5)").await;
        let (_, code) = socks5_connect(socks_port, "127.0.0.1", free_port()).await;
        assert_eq!(code, 5, "closed port should be reported as connection refused");

        let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
        let mut request = vec![4, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        request.extend_from_slice(&[0, 0, 0, 1, 0]);
        request.extend_from_slice(b"localhost\0");
        s.write_all(&request).await.unwrap();
        let mut reply = [0u8; 8];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x5a, "SOCKS4a CONNECT should be granted");
        assert_echo_on(s, b"hello via -D (socks4a)").await;

        // A real client: curl through the proxy with remote DNS.
        let http_port = spawn_http_ok().await;
        for flag in ["--socks5-hostname", "--socks4a"] {
            let output = tokio::process::Command::new("curl")
                .args(["-s", "--max-time", "10", flag, &format!("127.0.0.1:{socks_port}")])
                .arg(format!("http://localhost:{http_port}/"))
                .output()
                .await
                .expect("curl must be installed");
            assert_eq!(String::from_utf8_lossy(&output.stdout), "ok", "curl {flag}");
        }

        // Stopping closes the listeners, locally and on the server.
        for id in ["L", "R", "D"] {
            manager.stop(id).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        for port in [local_port, remote_port, socks_port] {
            assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err(), "port {port} still open");
        }
        assert!(manager.list_active().await.is_empty());
        {
            let events = events.lock().unwrap();
            for id in ["L", "R", "D"] {
                assert!(events.iter().any(|e| e.rule_id == id && e.state == "started"), "{id} started");
                assert!(
                    events.iter().any(|e| e.rule_id == id && e.state == "stopped" && e.error.is_none()),
                    "{id} stopped cleanly"
                );
            }
        }
        let _ = std::fs::remove_dir_all(config_home);
    }

    #[test]
    fn endpoint_display_brackets_ipv6() {
        assert_eq!(Endpoint::new("::1", 22).to_string(), "[::1]:22");
        assert_eq!(Endpoint::new("db", 5432).to_string(), "db:5432");
    }
}
