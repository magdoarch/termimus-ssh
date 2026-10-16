use russh::client::Handle;
use russh::{ChannelMsg, Disconnect};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};

use crate::db::Database;
use crate::ssh::{JumpHostConfig, SshAuth, SshClientHandler};

pub struct ActiveTunnel {
    /// Distinguishes this run from a later restart of the same rule, so a
    /// finishing task only removes its own entry.
    generation: u64,
    /// `None` while the SSH connection is still being established.
    stop_tx: Option<oneshot::Sender<()>>,
}

/// How often a running tunnel checks whether its SSH connection is gone.
const CONNECTION_CHECK_INTERVAL: Duration = Duration::from_secs(5);

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

    pub async fn is_active(&self, rule_id: &str) -> bool {
        self.active
            .lock()
            .await
            .get(rule_id)
            .is_some_and(|t| t.stop_tx.is_some())
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

    /// Start a local port forward: listen on local_address:local_port, and for
    /// every incoming TCP connection, open a direct-tcpip channel to
    /// remote_address:remote_port on the far side of the SSH connection.
    pub async fn start_local_forward(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        rule_id: String,
        address: String,
        port: u16,
        username: String,
        auth: SshAuth,
        local_address: String,
        local_port: u16,
        remote_address: String,
        remote_port: u16,
        jump_host: Option<JumpHostConfig>,
    ) -> Result<(), String> {
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

        let setup = async {
            let (handle, jump_handle) = crate::ssh::connect_authenticated(
                db,
                &address,
                port,
                &username,
                &auth,
                jump_host.as_ref(),
            )
            .await
            .map_err(|e| format!("Tunnel: {e}"))?;

            let bind_addr = format!("{local_address}:{local_port}");
            match TcpListener::bind(&bind_addr).await {
                Ok(listener) => Ok((handle, jump_handle, listener)),
                Err(e) => {
                    disconnect_quietly(&handle, jump_handle.as_ref()).await;
                    Err(format!("Failed to bind {bind_addr}: {e}"))
                }
            }
        };
        let (handle, jump_handle, listener) = match setup.await {
            Ok(v) => v,
            Err(e) => {
                remove_if_current(&self.active, &rule_id, generation).await;
                return Err(e);
            }
        };

        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let handle = Arc::new(handle);
        let status_event = format!("tunnel-status-{rule_id}");
        let app_for_status = app.clone();
        let rule_id_for_task = rule_id.clone();
        let active_for_task = self.active.clone();

        // Publish the stop handle before the task can possibly finish and
        // remove the entry. If the rule was stopped while connecting, bail out.
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

        tokio::spawn(async move {
            let _ = app_for_status.emit(&status_event, "started");
            let mut connection_check = tokio::time::interval(CONNECTION_CHECK_INTERVAL);
            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        break;
                    }
                    _ = connection_check.tick() => {
                        if handle.is_closed() || jump_handle.as_ref().is_some_and(|j| j.is_closed()) {
                            eprintln!("Tunnel {rule_id_for_task}: SSH connection closed");
                            break;
                        }
                    }
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, peer_addr)) => {
                                let handle = handle.clone();
                                let remote_address = remote_address.clone();
                                let originator_ip = peer_addr.ip().to_string();
                                let originator_port = peer_addr.port() as u32;
                                tokio::spawn(async move {
                                    if let Err(e) = forward_connection(
                                        handle,
                                        stream,
                                        remote_address,
                                        remote_port,
                                        originator_ip,
                                        originator_port,
                                    ).await {
                                        eprintln!("Tunnel forwarding error: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("Tunnel accept error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
            // Whatever ended the loop (stop, listener error, dropped SSH
            // connection), tear the connection down and forget the rule so it
            // can be started again.
            drop(listener);
            disconnect_quietly(&handle, jump_handle.as_ref()).await;
            remove_if_current(&active_for_task, &rule_id_for_task, generation).await;
            let _ = app_for_status.emit(&format!("tunnel-status-{rule_id_for_task}"), "stopped");
        });

        Ok(())
    }

    pub async fn stop(&self, rule_id: &str) -> Result<(), String> {
        let mut active = self.active.lock().await;
        // Removing a still-connecting entry makes start_local_forward abort.
        if let Some(tunnel) = active.remove(rule_id) {
            if let Some(stop_tx) = tunnel.stop_tx {
                let _ = stop_tx.send(());
            }
        }
        Ok(())
    }
}

async fn remove_if_current(
    active: &Mutex<HashMap<String, ActiveTunnel>>,
    rule_id: &str,
    generation: u64,
) {
    let mut active = active.lock().await;
    if active.get(rule_id).is_some_and(|t| t.generation == generation) {
        active.remove(rule_id);
    }
}

async fn disconnect_quietly(
    handle: &Handle<SshClientHandler>,
    jump_handle: Option<&Handle<SshClientHandler>>,
) {
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    if let Some(jump) = jump_handle {
        let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

async fn forward_connection(
    handle: Arc<Handle<SshClientHandler>>,
    mut stream: TcpStream,
    remote_address: String,
    remote_port: u16,
    originator_ip: String,
    originator_port: u32,
) -> Result<(), String> {
    let _ = stream.set_nodelay(true);
    let mut channel = handle
        .channel_open_direct_tcpip(remote_address, remote_port as u32, originator_ip, originator_port)
        .await
        .map_err(|e| format!("Failed to open direct-tcpip channel: {e}"))?;

    let mut buf = vec![0u8; 32 * 1024];
    let mut stream_closed = false;

    loop {
        tokio::select! {
            read_result = stream.read(&mut buf), if !stream_closed => {
                match read_result {
                    Ok(0) => {
                        stream_closed = true;
                        let _ = channel.eof().await;
                    }
                    Ok(n) => {
                        if channel.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { ref data }) => {
                        if stream.write_all(data).await.is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
