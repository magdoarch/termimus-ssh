use russh::client::Handle;
use russh::ChannelMsg;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};

use crate::db::Database;
use crate::ssh::{JumpHostConfig, SshAuth, SshClientHandler};

pub struct ActiveTunnel {
    pub rule_id: String,
    stop_tx: oneshot::Sender<()>,
}

pub struct TunnelManager {
    active: Mutex<HashMap<String, ActiveTunnel>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        TunnelManager {
            active: Mutex::new(HashMap::new()),
        }
    }

    pub async fn is_active(&self, rule_id: &str) -> bool {
        self.active.lock().await.contains_key(rule_id)
    }

    pub async fn list_active(&self) -> Vec<String> {
        self.active.lock().await.keys().cloned().collect()
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
        {
            let active = self.active.lock().await;
            if active.contains_key(&rule_id) {
                return Err("Tunnel is already running".to_string());
            }
        }

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
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|e| format!("Failed to bind {bind_addr}: {e}"))?;

        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let handle = Arc::new(handle);
        let status_event = format!("tunnel-status-{rule_id}");
        let app_for_status = app.clone();
        let rule_id_for_task = rule_id.clone();

        tokio::spawn(async move {
            // The bastion connection carries the tunnel's SSH session; keep it
            // alive for as long as the listener runs.
            let _jump_handle = jump_handle;
            let _ = app_for_status.emit(&status_event, "started");
            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        break;
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
            let _ = app_for_status.emit(&format!("tunnel-status-{rule_id_for_task}"), "stopped");
        });

        let mut active = self.active.lock().await;
        active.insert(rule_id.clone(), ActiveTunnel { rule_id, stop_tx });

        Ok(())
    }

    pub async fn stop(&self, rule_id: &str) -> Result<(), String> {
        let mut active = self.active.lock().await;
        if let Some(tunnel) = active.remove(rule_id) {
            let _ = tunnel.stop_tx.send(());
        }
        Ok(())
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
