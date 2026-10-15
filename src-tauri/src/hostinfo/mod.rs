//! Live information about SSH hosts, gathered with exec channels on their
//! (shared) connection: server stats here, Docker containers in `docker`.

pub mod stats;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::{oneshot, Mutex};

use crate::db::Database;
use crate::ssh::conn::sh_command;
use crate::ssh::{ConnectionPool, Route, SshConnection};

/// Longest a single stats sample may take.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(15);
const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Payload of `host-stats-{monitorId}`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorEvent {
    pub stats: Option<stats::HostStats>,
    pub error: Option<String>,
}

/// Running stats monitors, by the id the UI gave them.
#[derive(Default)]
pub struct HostMonitor {
    running: Mutex<HashMap<String, oneshot::Sender<()>>>,
}

impl HostMonitor {
    /// Sample the host every `interval`, emitting `host-stats-{monitor_id}`
    /// until stopped or the connection ends. Returns once connected; the
    /// connection stays open (and shared) while the monitor runs.
    pub async fn start(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        pool: &ConnectionPool,
        route: Route,
        monitor_id: String,
        interval: Duration,
    ) -> Result<(), String> {
        self.stop(&monitor_id).await;
        let quiet = |_: u8, _: &str, _: &str| {};
        let (connection, _) = pool.connect(&db, &route, &quiet).await?;
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        self.running.lock().await.insert(monitor_id.clone(), stop_tx);
        let interval = interval.max(MIN_INTERVAL);
        let event = format!("host-stats-{monitor_id}");
        tokio::spawn(async move {
            let mut previous = None;
            loop {
                let payload = match sample(&connection, previous.as_ref()).await {
                    Ok((stats, counters)) => {
                        previous = Some(counters);
                        MonitorEvent { stats: Some(stats), error: None }
                    }
                    Err(e) => MonitorEvent { stats: None, error: Some(e) },
                };
                let _ = app.emit(&event, payload);
                if connection.is_closed() {
                    let _ = app.emit(
                        &event,
                        MonitorEvent { stats: None, error: Some("The SSH connection was closed".to_string()) },
                    );
                    break;
                }
                tokio::select! {
                    // Stopped, or replaced by a new monitor with this id.
                    _ = &mut stop_rx => break,
                    _ = tokio::time::sleep(interval) => {}
                }
            }
        });
        Ok(())
    }

    pub async fn stop(&self, monitor_id: &str) {
        if let Some(stop) = self.running.lock().await.remove(monitor_id) {
            let _ = stop.send(());
        }
    }
}

async fn sample(
    connection: &SshConnection,
    previous: Option<&stats::Counters>,
) -> Result<(stats::HostStats, stats::Counters), String> {
    let output = tokio::time::timeout(
        SAMPLE_TIMEOUT,
        connection.exec(&sh_command(stats::STATS_SCRIPT), None, 256 * 1024),
    )
    .await
    .map_err(|_| "The server took too long to answer".to_string())??;
    stats::parse(&output.stdout_text(), previous)
}
