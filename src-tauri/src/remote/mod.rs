//! Remote desktop sessions (VNC and RDP). Each session runs a protocol client
//! in a background task that streams frames to the frontend over a binary
//! `tauri::ipc::Channel` (see `frame.rs`) and receives input through
//! `RemoteDesktopManager::send_input`.

mod frame;
pub mod rdp;
mod rdp_clipboard;
pub mod input;
mod vnc;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};

use serde::Deserialize;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex, RwLock};
use ::vnc::VncClient;
use zeroize::Zeroizing;

use crate::db::Database;
use crate::ssh::{ConnectionPool, Route, SshProgressPayload};
pub use input::RemoteInput;

/// Per-host VNC settings, stored as JSON in `hosts.protocol_options`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VncOptions {
    /// Ignore all keyboard/mouse/clipboard input.
    pub view_only: bool,
    /// Ask the server to disconnect other viewers.
    pub exclusive: bool,
}

/// Per-host RDP settings, stored as JSON in `hosts.protocol_options`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RdpOptions {
    /// Windows / Active Directory domain (optional).
    pub domain: Option<String>,
    /// Ignore all keyboard/mouse input.
    pub view_only: bool,
}

pub enum RemoteProtocolTarget {
    Vnc {
        password: Option<Zeroizing<String>>,
        options: VncOptions,
    },
    Rdp {
        login: rdp::RdpLogin,
        view_only: bool,
        /// Requested desktop size (the pane size at connect time).
        desktop: (u16, u16),
    },
}

pub struct RemoteTarget {
    pub address: String,
    pub port: u16,
    /// Jump hosts in front of the server (outermost first); empty = direct.
    pub jump_route: Route,
    pub protocol: RemoteProtocolTarget,
}

/// A handshaken protocol client, ready for its session loop.
enum Connected {
    Vnc { client: VncClient, view_only: bool },
    Rdp { connection: rdp::RdpConnection, view_only: bool },
}

struct RemoteSession {
    input_tx: mpsc::UnboundedSender<RemoteInput>,
}

pub struct RemoteDesktopManager {
    sessions: Arc<RwLock<HashMap<String, Arc<RemoteSession>>>>,
    connecting: Mutex<HashSet<String>>,
    /// Session ids whose tab was closed while the connect was in flight.
    cancelled: Mutex<HashSet<String>>,
}

impl RemoteDesktopManager {
    pub fn new() -> Self {
        RemoteDesktopManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            connecting: Mutex::new(HashSet::new()),
            cancelled: Mutex::new(HashSet::new()),
        }
    }

    pub async fn connect(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        pool: &ConnectionPool,
        session_id: String,
        target: RemoteTarget,
        on_frame: Channel<InvokeResponseBody>,
    ) -> Result<(), String> {
        {
            let mut connecting = self.connecting.lock().await;
            if !connecting.insert(session_id.clone()) {
                return Err("Connection already in progress for this session".to_string());
            }
        }
        self.cancelled.lock().await.remove(&session_id);

        let result = self
            .do_connect(app, db, pool, session_id.clone(), target, on_frame)
            .await;

        self.connecting.lock().await.remove(&session_id);
        self.cancelled.lock().await.remove(&session_id);
        result
    }

    async fn do_connect(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        pool: &ConnectionPool,
        session_id: String,
        target: RemoteTarget,
        on_frame: Channel<InvokeResponseBody>,
    ) -> Result<(), String> {
        let progress_event = format!("remote-progress-{session_id}");
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
        let fail = |message: String| {
            emit_progress(1, "error", &message, true);
            message
        };

        // A retry reuses the session id; drop whatever is left of the old one.
        self.sessions.write().await.remove(&session_id);

        let RemoteTarget { address, port, jump_route, protocol } = target;
        let connecting_msg = match jump_route.last() {
            Some(jump) => format!("Connecting to {address}:{port} via jump host {}...", jump.target()),
            None => format!("Connecting to {address}:{port}..."),
        };
        emit_progress(1, "connecting", &connecting_msg, false);

        // Through the jump hosts' (possibly shared) SSH connection, which
        // must stay up as long as the session runs.
        let progress = |step: u8, step_name: &str, message: &str| emit_progress(step, step_name, message, false);
        let (stream, jump) = crate::ssh::conn::open_stream(pool, &db, &jump_route, &address, port, &progress)
            .await
            .map_err(|e| fail(e))?;
        if self.is_cancelled(&session_id).await {
            return Err("Connection cancelled".to_string());
        }

        let handshake = match protocol {
            RemoteProtocolTarget::Vnc { password, options } => {
                emit_progress(3, "authenticating", "VNC handshake...", false);
                vnc::handshake(stream, password, !options.exclusive)
                    .await
                    .map(|client| Connected::Vnc { client, view_only: options.view_only })
            }
            RemoteProtocolTarget::Rdp { login, view_only, desktop } => {
                let (progress_app, progress_event, rdp_address) = (app.clone(), progress_event.clone(), address.clone());
                let progress = move |step: u8, step_name: &str, message: &str| {
                    let _ = progress_app.emit(
                        &progress_event,
                        SshProgressPayload {
                            step,
                            step_name: step_name.to_string(),
                            message: message.to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            is_error: false,
                        },
                    );
                };
                run_not_send(move || async move {
                    rdp::connect(stream, db, &rdp_address, port, login, desktop, progress).await
                })
                .await
                .map(|connection| Connected::Rdp { connection, view_only })
            }
        };
        let connected = handshake.map_err(|e| fail(e))?;

        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let session = Arc::new(RemoteSession { input_tx });
        self.sessions.write().await.insert(session_id.clone(), session.clone());

        // A disconnect may have landed between the handshake and the insert.
        if self.is_cancelled(&session_id).await {
            self.sessions.write().await.remove(&session_id);
            if let Connected::Vnc { client, .. } = &connected {
                let _ = client.close().await;
            }
            drop(connected);
            return Err("Connection cancelled".to_string());
        }

        emit_progress(5, "ready", "Connected", false);

        let sessions = self.sessions.clone();
        let weak_session: Weak<RemoteSession> = Arc::downgrade(&session);
        drop(session);
        // Boxing as `dyn Future + Send` checks Send on the concrete protocol
        // futures here; inside the spawned block rustc's higher-ranked Send
        // inference fails on vnc-rs's borrowed client futures.
        let session_loop: std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> =
            match connected {
                Connected::Vnc { client, view_only } => Box::pin(run_vnc(
                    client,
                    input_rx,
                    on_frame,
                    app.clone(),
                    session_id.clone(),
                    view_only,
                )),
                Connected::Rdp { connection, view_only } => Box::pin(run_rdp(
                    connection,
                    input_rx,
                    on_frame,
                    app.clone(),
                    session_id.clone(),
                    view_only,
                )),
            };
        tauri::async_runtime::spawn(async move {
            let result = session_loop.await;
            drop(jump);
            {
                let mut map = sessions.write().await;
                if map
                    .get(&session_id)
                    .is_some_and(|s| std::ptr::eq(Arc::as_ptr(s), weak_session.as_ptr()))
                {
                    map.remove(&session_id);
                }
            }
            let _ = app.emit(&format!("remote-closed-{session_id}"), result.err());
        });

        Ok(())
    }

    async fn is_cancelled(&self, session_id: &str) -> bool {
        self.cancelled.lock().await.contains(session_id)
    }

    pub async fn send_input(&self, session_id: &str, events: Vec<RemoteInput>) -> Result<(), String> {
        let input_tx = self
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|s| s.input_tx.clone())
            .ok_or_else(|| "Remote session not found".to_string())?;
        for event in events {
            input_tx
                .send(event)
                .map_err(|_| "Remote session has ended".to_string())?;
        }
        Ok(())
    }

    /// Ends the session (its task stops once the input channel closes), or
    /// cancels a connect that is still in flight.
    pub async fn disconnect(&self, session_id: &str) {
        let removed = self.sessions.write().await.remove(session_id).is_some();
        if !removed && self.connecting.lock().await.contains(session_id) {
            self.cancelled.lock().await.insert(session_id.to_string());
        }
    }

    pub async fn disconnect_all(&self) {
        self.sessions.write().await.clear();
    }
}

// Owned-argument wrappers: borrowing inside the spawned task's `match` trips
// rustc's higher-ranked `Send` inference for the combined future.
async fn run_vnc(
    client: VncClient,
    input_rx: mpsc::UnboundedReceiver<RemoteInput>,
    on_frame: Channel<InvokeResponseBody>,
    app: AppHandle,
    session_id: String,
    view_only: bool,
) -> Result<(), String> {
    let result = vnc::run(&client, input_rx, &on_frame, &app, &session_id, view_only).await;
    let _ = client.close().await;
    result
}

/// IronRDP's async helpers hold `&dyn` trait objects across awaits, so its
/// futures aren't `Send`. Drive them on a blocking-pool thread with
/// `block_on`, which doesn't require `Send`.
async fn run_not_send<F, Fut, T>(make: F) -> Result<T, String>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>>,
    T: Send + 'static,
{
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || handle.block_on(make()))
        .await
        .map_err(|e| format!("RDP task failed: {e}"))?
}

async fn run_rdp(
    connection: rdp::RdpConnection,
    input_rx: mpsc::UnboundedReceiver<RemoteInput>,
    on_frame: Channel<InvokeResponseBody>,
    app: AppHandle,
    session_id: String,
    view_only: bool,
) -> Result<(), String> {
    run_not_send(move || async move {
        rdp::run(connection, input_rx, &on_frame, &app, &session_id, view_only).await
    })
    .await
}


