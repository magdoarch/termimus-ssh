//! End-to-end checks against a real sshd, ignored by default:
//!
//! SSH_TEST_ADDR=127.0.0.1:2222 SSH_TEST_USER=root SSH_TEST_KEY=/path/to/key \
//!   cargo test -- --ignored ssh::e2e_tests
//!
//! The user must be able to log in with the key, open shells and SFTP, and
//! forward TCP back to the server itself (used as its own jump host).
//! `SSH_TEST_DIR` (default /tmp) is where files are created on the server.

use std::sync::Arc;
use std::time::Duration;

use russh::client::Msg;
use russh::Channel;

use super::*;

pub(crate) struct TestServer {
    pub address: String,
    pub port: u16,
    pub user: String,
    pub key: String,
    pub dir: String,
}

impl TestServer {
    pub fn from_env() -> Self {
        let addr = std::env::var("SSH_TEST_ADDR").expect("SSH_TEST_ADDR");
        let (address, port) = addr.rsplit_once(':').expect("SSH_TEST_ADDR is host:port");
        TestServer {
            address: address.to_string(),
            port: port.parse().expect("port"),
            user: std::env::var("SSH_TEST_USER").expect("SSH_TEST_USER"),
            key: std::fs::read_to_string(std::env::var("SSH_TEST_KEY").expect("SSH_TEST_KEY")).unwrap(),
            dir: std::env::var("SSH_TEST_DIR").unwrap_or_else(|_| "/tmp".to_string()),
        }
    }

    pub fn auth(&self) -> SshAuth {
        SshAuth::PrivateKey { pem: self.key.clone(), passphrase: None }
    }

    /// The server reached through itself as the jump host.
    pub fn jump(&self) -> JumpHostConfig {
        JumpHostConfig {
            address: self.address.clone(),
            port: self.port,
            username: self.user.clone(),
            auth: self.auth(),
        }
    }
}

/// Output of `channel` until `needle` shows up (or the channel ends).
pub(crate) async fn read_until(channel: &mut Channel<Msg>, needle: &str) -> String {
    let mut out = Vec::new();
    let read = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                    out.extend_from_slice(&data);
                    if !needle.is_empty() && String::from_utf8_lossy(&out).contains(needle) {
                        break;
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(15), read).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn shell_with_pty_runs_commands_and_resizes() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let (handle, _) = connect_authenticated(db, &server.address, server.port, &server.user, &server.auth(), None)
        .await
        .unwrap();
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(true, "xterm-256color", 100, 30, 0, 0, &[]).await.unwrap();
    channel.request_shell(true).await.unwrap();
    channel.data(&b"stty size; echo marker-$((40+2))\n"[..]).await.unwrap();
    let out = read_until(&mut channel, "marker-42").await;
    assert!(out.contains("30 100"), "{out}");

    channel.window_change(120, 40, 0, 0).await.unwrap();
    channel.data(&b"stty size; echo done-$((1+1))\n"[..]).await.unwrap();
    let out = read_until(&mut channel, "done-2").await;
    assert!(out.contains("40 120"), "{out}");
    channel.data(&b"exit\n"[..]).await.unwrap();
    read_until(&mut channel, "").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn sftp_round_trip() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let sftp = crate::sftp::SftpManager::new();
    sftp.connect(db, "e2e".into(), "host".into(), server.address.clone(), server.port, server.user.clone(), server.auth(), None)
        .await
        .unwrap();
    let dir = format!("{}/termimus-sftp-e2e-{}", server.dir, uuid::Uuid::new_v4());
    let file = format!("{dir}/notes.txt");
    sftp.mkdir("e2e", &dir).await.unwrap();
    sftp.write_text_file("e2e", &file, "hello over sftp").await.unwrap();
    assert_eq!(sftp.read_text_file("e2e", &file).await.unwrap(), "hello over sftp");
    let entries = sftp.list("e2e", &dir).await.unwrap();
    assert_eq!(entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["notes.txt"]);
    sftp.delete("e2e", &file, false).await.unwrap();
    sftp.delete("e2e", &dir, true).await.unwrap();
    sftp.disconnect("e2e").await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn exec_through_jump_host() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let jump = server.jump();
    let (handle, jump_handle) =
        connect_authenticated(db, "localhost", server.port, &server.user, &server.auth(), Some(&jump))
            .await
            .unwrap();
    assert!(jump_handle.is_some());
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo via-$((6*7))").await.unwrap();
    let out = read_until(&mut channel, "via-42").await;
    assert!(out.contains("via-42"), "{out}");
}
