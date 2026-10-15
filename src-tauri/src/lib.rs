pub mod biometric;
pub mod commands;
pub mod db;
pub mod pty;
pub mod remote;
pub mod sftp;
pub mod ssh;
pub mod sshconfig;
pub mod sshkey;
pub mod tunnel;
pub mod vault;

use commands::AppState;
use db::Database;
use pty::PtyManager;
use remote::RemoteDesktopManager;
use sftp::SftpManager;
use ssh::SessionManager;
use std::sync::Arc;
use tauri::Manager;
use tunnel::TunnelManager;
use vault::VaultManager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db = Arc::new(Database::new().expect("Failed to initialize SQLite database"));
    let vault = Arc::new(VaultManager::new());
    let ssh = Arc::new(SessionManager::new());
    let sftp = Arc::new(SftpManager::new());
    let tunnel = Arc::new(TunnelManager::new());
    let pty = Arc::new(PtyManager::new());
    let remote = Arc::new(RemoteDesktopManager::new());
    let pool = Arc::new(ssh::ConnectionPool::new());

    let state = AppState { db, vault, ssh, sftp, tunnel, pty, remote, pool };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(state)
        .setup(|app| {
            // Logins can ask the user for 2FA codes through the UI.
            ssh::auth_prompt::init(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_setup,
            commands::vault_unlock,
            commands::vault_lock,
            commands::vault_keyring_save,
            commands::vault_keyring_unlock,
            commands::vault_keyring_clear,
            commands::vault_keyring_has_key,
            commands::vault_biometric_supported,
            commands::vault_biometric_unlock,
            commands::vault_change_password,
            commands::vault_reset,
            commands::host_list,
            commands::host_save,
            commands::host_delete,
            commands::folder_list,
            commands::folder_save,
            commands::folder_delete,
            commands::ssh_connect,
            commands::ssh_write,
            commands::ssh_resize,
            commands::ssh_disconnect,
            commands::local_pty_default_shell,
            commands::local_pty_spawn,
            commands::local_pty_write,
            commands::local_pty_resize,
            commands::local_pty_kill,
            commands::key_generate,
            commands::key_derive_public,
            commands::keychain_list,
            commands::keychain_save_key,
            commands::keychain_save_identity,
            commands::keychain_delete,
            commands::keychain_get_public_key,
            commands::keychain_get_private_key,
            commands::host_get_password,
            commands::credential_get_secret,
            commands::sftp_connect,
            commands::sftp_list,
            commands::sftp_mkdir,
            commands::sftp_delete,
            commands::sftp_rename,
            commands::sftp_upload,
            commands::sftp_download,
            commands::sftp_disconnect,
            commands::sftp_read_file,
            commands::sftp_write_file,
            commands::local_home_dir,
            commands::local_list,
            commands::local_mkdir,
            commands::local_delete,
            commands::local_read_file,
            commands::local_write_file,
            commands::tunnel_rule_list,
            commands::tunnel_rule_save,
            commands::tunnel_rule_delete,
            commands::tunnel_start,
            commands::tunnel_stop,
            commands::tunnel_active_list,
            commands::snippet_list,
            commands::snippet_save,
            commands::snippet_delete,
            commands::workspace_preset_list,
            commands::workspace_preset_save,
            commands::workspace_preset_delete,
            commands::ping_host,
            commands::ping_hosts,
            commands::known_host_list,
            commands::known_host_delete,
            commands::ssh_config_preview,
            commands::ssh_config_import,
            commands::backup_export,
            commands::backup_import,
            commands::sync_test_connection,
            commands::sync_push,
            commands::sync_pull,
            commands::sync_get_devices,
            commands::sync_secrets_save,
            commands::sync_secrets_load,
            commands::remote_connect,
            commands::remote_input,
            commands::remote_disconnect,
            commands::ssh_auth_prompt_respond,
            commands::ssh_set_connection_sharing,
        ])
        .build(tauri::generate_context!())
        .expect("error while building termimus application")
        .run(|app_handle, event| {
            // Best-effort graceful shutdown: send a proper SSH disconnect for
            // every live session before the process exits. Bounded by a timeout
            // so quitting never hangs on dead sockets.
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let ssh = app_handle.state::<AppState>().ssh.clone();
                let remote = app_handle.state::<AppState>().remote.clone();
                let pool = app_handle.state::<AppState>().pool.clone();
                tauri::async_runtime::block_on(async move {
                    remote.disconnect_all().await;
                    ssh.disconnect_all().await;
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), pool.disconnect_all()).await;
                });
            }
        });
}
