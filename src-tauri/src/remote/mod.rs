//! Remote desktop sessions (VNC for now). Each session runs a protocol client
//! in a background task that streams frames to the frontend over a binary
//! `tauri::ipc::Channel` (see `frame.rs`) and receives input through
//! `RemoteDesktopManager::send_input`.

mod frame;
pub mod input;
mod vnc;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};

use russh::client::Handle;
use russh::Disconnect;
use serde::Deserialize;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex, RwLock};
use zeroize::Zeroizing;

use crate::db::Database;
use crate::ssh::{JumpHostConfig, SshClientHandler, SshProgressPayload};
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

pub struct VncTarget {
    pub address: String,
    pub port: u16,
    pub password: Option<Zeroizing<String>>,
    pub jump: Option<JumpHostConfig>,
    pub options: VncOptions,
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

impl Default for RemoteDesktopManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteDesktopManager {
    pub fn new() -> Self {
        RemoteDesktopManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            connecting: Mutex::new(HashSet::new()),
            cancelled: Mutex::new(HashSet::new()),
        }
    }

    pub async fn connect_vnc(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        session_id: String,
        target: VncTarget,
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
            .do_connect_vnc(app, db, session_id.clone(), target, on_frame)
            .await;

        self.connecting.lock().await.remove(&session_id);
        self.cancelled.lock().await.remove(&session_id);
        result
    }

    async fn do_connect_vnc(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        session_id: String,
        target: VncTarget,
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

        let VncTarget { address, port, password, jump, options } = target;
        let connecting_msg = match &jump {
            Some(j) => format!("Connecting to {address}:{port} via Jump Host {}:{}...", j.address, j.port),
            None => format!("Connecting to {address}:{port}..."),
        };
        emit_progress(1, "connecting", &connecting_msg, false);

        let (stream, jump_handle) = crate::ssh::open_transport(db, &address, port, jump.as_ref())
            .await
            .map_err(fail)?;
        if self.is_cancelled(&session_id).await {
            disconnect_jump(jump_handle).await;
            return Err("Connection cancelled".to_string());
        }

        emit_progress(3, "authenticating", "VNC handshake...", false);
        let client = match vnc::handshake(stream, password, !options.exclusive).await {
            Ok(c) => c,
            Err(e) => {
                disconnect_jump(jump_handle).await;
                return Err(fail(e));
            }
        };

        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let session = Arc::new(RemoteSession { input_tx });
        self.sessions.write().await.insert(session_id.clone(), session.clone());

        // A disconnect may have landed between the handshake and the insert.
        if self.is_cancelled(&session_id).await {
            self.sessions.write().await.remove(&session_id);
            let _ = client.close().await;
            disconnect_jump(jump_handle).await;
            return Err("Connection cancelled".to_string());
        }

        emit_progress(5, "ready", "Connected", false);

        let sessions = self.sessions.clone();
        let weak_session: Weak<RemoteSession> = Arc::downgrade(&session);
        drop(session);
        tauri::async_runtime::spawn(async move {
            let result = vnc::run(&client, input_rx, &on_frame, &app, &session_id, options.view_only).await;
            let _ = client.close().await;
            disconnect_jump(jump_handle).await;
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

async fn disconnect_jump(jump_handle: Option<Handle<SshClientHandler>>) {
    if let Some(jump) = jump_handle {
        let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}
