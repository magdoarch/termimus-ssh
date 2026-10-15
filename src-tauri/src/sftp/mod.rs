use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::db::Database;
use crate::ssh::{ConnectionPool, Route, SshConnection};

/// Largest file the inline text editor will load.
const MAX_EDITOR_FILE_SIZE: u64 = 5 * 1024 * 1024;
/// How long the server may take to start its SFTP subsystem.
const SUBSYSTEM_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<u64>,
    pub permissions: Option<u32>,
}

pub struct SftpConnection {
    pub session_id: String,
    pub host_id: String,
    pub sftp: SftpSession,
    /// Keeps the SSH connection open; it may be shared with terminal tabs.
    _connection: Arc<SshConnection>,
}

pub struct SftpManager {
    connections: Mutex<HashMap<String, Arc<SftpConnection>>>,
}

impl SftpManager {
    pub fn new() -> Self {
        SftpManager {
            connections: Mutex::new(HashMap::new()),
        }
    }

    // Clone the handle out of the map so slow IO runs without holding the
    // manager lock; holding it would serialize every SFTP call behind the
    // longest-running transfer.
    async fn connection(&self, session_id: &str) -> Result<Arc<SftpConnection>, String> {
        let connections = self.connections.lock().await;
        connections
            .get(session_id)
            .cloned()
            .ok_or_else(|| "SFTP session not found. Please connect first.".to_string())
    }

    /// Open SFTP on the host's connection, reusing one a terminal tab (or
    /// another SFTP pane) already has open, so there's no second login.
    pub async fn connect(
        &self,
        db: Arc<Database>,
        pool: &ConnectionPool,
        session_id: String,
        host_id: String,
        route: Route,
    ) -> Result<String, String> {
        let no_progress = |_: u8, _: &str, _: &str| {};
        let (mut connection, reused) = pool
            .connect(&db, &route, &no_progress)
            .await
            .map_err(|e| format!("SFTP: {e}"))?;

        let channel = match connection.open_session().await {
            Ok(channel) => channel,
            // A shared connection may be at the server's session limit.
            Err(russh::Error::ChannelOpenFailure(_)) if reused => {
                connection = pool
                    .connect_new(&db, &route, &no_progress)
                    .await
                    .map_err(|e| format!("SFTP: {e}"))?;
                connection
                    .open_session()
                    .await
                    .map_err(|e| format!("Channel open failed: {e}"))?
            }
            Err(e) => return Err(format!("Channel open failed: {e}")),
        };

        // Wait for the server's answer: without an SFTP subsystem, the
        // session setup below would only time out.
        let mut channel = channel;
        let started = async {
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|e| format!("SFTP subsystem request failed: {e}"))?;
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Success) => return Ok(()),
                    Some(russh::ChannelMsg::Failure) => {
                        return Err("The server doesn't offer SFTP (no sftp subsystem in its sshd_config)".to_string())
                    }
                    Some(russh::ChannelMsg::Close) | None => return Err("The server closed the SFTP channel".to_string()),
                    Some(_) => {}
                }
            }
        };
        match tokio::time::timeout(SUBSYSTEM_REPLY_TIMEOUT, started).await {
            Ok(Ok(())) => {}
            failed => {
                // The connection may be shared: close just this channel.
                let _ = channel.close().await;
                return Err(match failed {
                    Ok(Err(e)) => e,
                    _ => "The server didn't answer the SFTP request".to_string(),
                });
            }
        }

        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| format!("SFTP initialization failed: {e}"))?;

        let initial_path = sftp
            .canonicalize(".")
            .await
            .unwrap_or_else(|_| "/".to_string());

        let conn = Arc::new(SftpConnection {
            session_id: session_id.clone(),
            host_id,
            sftp,
            _connection: connection,
        });

        let mut connections = self.connections.lock().await;
        connections.insert(session_id, conn);

        Ok(initial_path)
    }

    pub async fn list(&self, session_id: &str, path: &str) -> Result<Vec<FileEntry>, String> {
        let conn = self.connection(session_id).await?;

        let entries = conn
            .sftp
            .read_dir(path)
            .await
            .map_err(|e| format!("Failed to read remote directory: {e}"))?;

        let mut list = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            // A READDIR name is a single path component; anything containing a
            // separator or NUL is a malicious/broken server trying to make a
            // recursive download escape the chosen local directory.
            if name.is_empty() || name.contains('/') || name.contains('\0') {
                eprintln!("[sftp] skipping invalid entry name from server: {name:?}");
                continue;
            }
            let file_type = entry.file_type();
            let is_dir = file_type.is_dir();
            let metadata = entry.metadata();
            let size = metadata.size.unwrap_or(0);
            let modified = metadata.mtime.map(|t| t as u64);
            let permissions = metadata.permissions;

            let full_path = if path.ends_with('/') {
                format!("{path}{name}")
            } else {
                format!("{path}/{name}")
            };

            list.push(FileEntry {
                name,
                path: full_path,
                is_dir,
                size,
                modified,
                permissions,
            });
        }

        // Sort: directories first, then alphabetical
        list.sort_by(|a, b| {
            if a.is_dir == b.is_dir {
                a.name.to_lowercase().cmp(&b.name.to_lowercase())
            } else if a.is_dir {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });

        Ok(list)
    }

    pub async fn mkdir(&self, session_id: &str, path: &str) -> Result<(), String> {
        let conn = self.connection(session_id).await?;
        conn.sftp
            .create_dir(path)
            .await
            .map_err(|e| format!("Failed to create remote directory: {e}"))
    }

    pub async fn delete(&self, session_id: &str, path: &str, is_dir: bool) -> Result<(), String> {
        let conn = self.connection(session_id).await?;
        if is_dir {
            conn.sftp
                .remove_dir(path)
                .await
                .map_err(|e| format!("Failed to delete remote folder: {e}"))
        } else {
            conn.sftp
                .remove_file(path)
                .await
                .map_err(|e| format!("Failed to delete remote file: {e}"))
        }
    }

    pub async fn rename(&self, session_id: &str, old_path: &str, new_path: &str) -> Result<(), String> {
        let conn = self.connection(session_id).await?;
        conn.sftp
            .rename(old_path, new_path)
            .await
            .map_err(|e| format!("Failed to rename: {e}"))
    }

    pub async fn upload_file(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
    ) -> Result<(), String> {
        let conn = self.connection(session_id).await?;

        let mut local_file = tokio::fs::File::open(local_path)
            .await
            .map_err(|e| format!("Failed to open local file: {e}"))?;

        let mut remote_file = conn
            .sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(|e| format!("Failed to create remote file: {e}"))?;

        let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks
        loop {
            let bytes_read = local_file
                .read(&mut buffer)
                .await
                .map_err(|e| format!("Error reading local file: {e}"))?;
            if bytes_read == 0 {
                break;
            }
            remote_file
                .write_all(&buffer[..bytes_read])
                .await
                .map_err(|e| format!("Error writing to remote file: {e}"))?;
        }
        remote_file
            .flush()
            .await
            .map_err(|e| format!("Error flushing remote file: {e}"))?;
        remote_file
            .shutdown()
            .await
            .map_err(|e| format!("Error closing remote file: {e}"))?;

        Ok(())
    }

    pub async fn download_file(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
    ) -> Result<(), String> {
        let conn = self.connection(session_id).await?;

        let mut remote_file = conn
            .sftp
            .open_with_flags(remote_path, OpenFlags::READ)
            .await
            .map_err(|e| format!("Failed to open remote file: {e}"))?;

        let mut local_file = tokio::fs::File::create(local_path)
            .await
            .map_err(|e| format!("Failed to create local file: {e}"))?;

        let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks
        loop {
            let bytes_read = remote_file
                .read(&mut buffer)
                .await
                .map_err(|e| format!("Error reading remote file: {e}"))?;
            if bytes_read == 0 {
                break;
            }
            local_file
                .write_all(&buffer[..bytes_read])
                .await
                .map_err(|e| format!("Error writing to local file: {e}"))?;
        }
        local_file
            .flush()
            .await
            .map_err(|e| format!("Error flushing local file: {e}"))?;

        Ok(())
    }

    pub async fn read_text_file(
        &self,
        session_id: &str,
        remote_path: &str,
    ) -> Result<String, String> {
        let conn = self.connection(session_id).await?;

        let metadata = conn
            .sftp
            .metadata(remote_path)
            .await
            .map_err(|e| format!("Cannot read file metadata: {e}"))?;

        if let Some(size) = metadata.size {
            if size > MAX_EDITOR_FILE_SIZE {
                return Err("File is too large to open in the inline editor (max 5 MB)".to_string());
            }
        }

        let file = conn
            .sftp
            .open_with_flags(remote_path, OpenFlags::READ)
            .await
            .map_err(|e| format!("Failed to open remote file: {e}"))?;

        // The size attribute is optional and the file may grow after stat, so
        // enforce the limit on what is actually read.
        let mut buffer = Vec::new();
        file.take(MAX_EDITOR_FILE_SIZE + 1)
            .read_to_end(&mut buffer)
            .await
            .map_err(|e| format!("Failed to read remote file: {e}"))?;
        if buffer.len() as u64 > MAX_EDITOR_FILE_SIZE {
            return Err("File is too large to open in the inline editor (max 5 MB)".to_string());
        }

        String::from_utf8(buffer)
            .map_err(|_| "File contains binary data and cannot be displayed as plain text".to_string())
    }

    pub async fn write_text_file(
        &self,
        session_id: &str,
        remote_path: &str,
        content: &str,
    ) -> Result<(), String> {
        let conn = self.connection(session_id).await?;

        let mut file = conn
            .sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(|e| format!("Failed to open remote file for writing: {e}"))?;

        file.write_all(content.as_bytes())
            .await
            .map_err(|e| format!("Failed to write to remote file: {e}"))?;

        file.flush()
            .await
            .map_err(|e| format!("Failed to flush remote file: {e}"))?;

        file.shutdown()
            .await
            .map_err(|e| format!("Failed to finalize remote file: {e}"))?;

        Ok(())
    }

    pub async fn disconnect(&self, session_id: &str) -> Result<(), String> {
        let removed = self.connections.lock().await.remove(session_id);
        // Ends the SFTP channel; the SSH connection closes once nothing else
        // uses it.
        if let Some(conn) = removed {
            let _ = conn.sftp.close().await;
        }
        Ok(())
    }
}

// Local filesystem helpers
pub fn list_local_directory(path: &Path) -> Result<Vec<FileEntry>, String> {
    let read_dir = fs::read_dir(path).map_err(|e| format!("Cannot read directory: {e}"))?;

    let mut entries = Vec::new();
    for entry in read_dir.flatten() {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let file_path = entry.path().to_string_lossy().to_string();
        let metadata = entry.metadata().ok();

        let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = metadata.and_then(|m| {
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs()))
        });

        entries.push(FileEntry {
            name: file_name,
            path: file_path,
            is_dir,
            size,
            modified,
            permissions: None,
        });
    }

    entries.sort_by(|a, b| {
        if a.is_dir == b.is_dir {
            a.name.to_lowercase().cmp(&b.name.to_lowercase())
        } else if a.is_dir {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });

    Ok(entries)
}

pub fn get_user_home() -> String {
    dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string())
}

pub fn read_local_text_file(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("Cannot read file metadata: {e}"))?;
    if metadata.len() > 5 * 1024 * 1024 {
        return Err("File is too large to open in the inline editor (max 5 MB)".to_string());
    }
    fs::read_to_string(path).map_err(|e| format!("Cannot read local file: {e}"))
}

pub fn write_local_text_file(path: &Path, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| format!("Cannot write to local file: {e}"))
}
