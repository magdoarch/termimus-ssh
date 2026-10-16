//! End-to-end checks against a real sshd, ignored by default:
//!
//! SSH_TEST_ADDR=127.0.0.1:2222 SSH_TEST_USER=root SSH_TEST_KEY=/path/to/key \
//!   cargo test -- --ignored ssh::e2e_tests
//!
//! The user must be able to log in with the key, open shells and SFTP, and
//! forward TCP back to the server itself (used as its own jump host, also
//! under the name `localhost`). The sharing checks expect sshd's default
//! `MaxSessions 10`. `SSH_TEST_DIR` (default /tmp) is where files are
//! created on the server.

use std::sync::Arc;
use std::time::Duration;

use russh::client::Msg;
use russh::Channel;

use super::*;
use crate::ssh::conn;

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

    /// A hop to the server under `address`, shared under `key`.
    pub fn hop(&self, address: &str, key: Option<&str>) -> Hop {
        Hop {
            key: key.map(str::to_string),
            address: address.to_string(),
            port: self.port,
            username: self.user.clone(),
            auth: SshAuth::PrivateKey { pem: self.key.clone(), passphrase: None },
            totp: None,
        }
    }

    /// Straight to the server, shared under `key`.
    pub fn route(&self, key: Option<&str>) -> Route {
        vec![self.hop(&self.address, key)]
    }
}

pub(crate) fn no_progress() -> impl Fn(u8, &str, &str) + Sync {
    |_: u8, _: &str, _: &str| {}
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
    let pool = ConnectionPool::new();
    let (connection, reused) = pool.connect(&db, &server.route(None), &no_progress()).await.unwrap();
    assert!(!reused);
    let mut channel = connection.open_session().await.unwrap();
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
    let pool = ConnectionPool::new();
    let sftp = crate::sftp::SftpManager::new();
    sftp.connect(db, &pool, "e2e".into(), "host".into(), server.route(Some("sftp-e2e")))
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
async fn exec_through_a_chain_of_jump_hosts() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let pool = ConnectionPool::new();
    // server -> localhost -> server: two jump hosts in front of the target.
    let route = vec![
        server.hop(&server.address, Some(">a")),
        server.hop("localhost", Some(">a>b")),
        server.hop(&server.address, Some(">a>b>c")),
    ];
    let steps = std::sync::Mutex::new(Vec::new());
    let record = |_: u8, _: &str, message: &str| steps.lock().unwrap().push(message.to_string());
    let (target, _) = pool.connect(&db, &route, &record).await.unwrap();
    let output = target.exec("echo via-$((6*7))", None, 1024).await.unwrap();
    assert_eq!(output.stdout_text().trim(), "via-42");
    assert_eq!(output.exit_status, Some(0));
    let steps = steps.lock().unwrap().join("\n");
    assert!(steps.contains("jump host 1/2"), "{steps}");
    assert!(steps.contains("jump host 2/2"), "{steps}");

    // Another host behind the same first jump host reuses its connection.
    let other = vec![server.hop(&server.address, Some(">a")), server.hop("localhost", Some(">a>d"))];
    let steps = std::sync::Mutex::new(Vec::new());
    let record = |_: u8, _: &str, message: &str| steps.lock().unwrap().push(message.to_string());
    let (other, reused) = pool.connect(&db, &other, &record).await.unwrap();
    assert!(!reused);
    assert!(steps.lock().unwrap().iter().any(|s| s.starts_with("Reusing the open connection to jump host")));
    assert_eq!(other.exec("echo second", None, 64).await.unwrap().stdout_text().trim(), "second");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn connections_are_shared_and_closed_after_the_last_user() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let pool = ConnectionPool::new();
    let route = server.route(Some("shared"));

    let (first, reused) = pool.connect(&db, &route, &no_progress()).await.unwrap();
    assert!(!reused);
    // Concurrent connects to the same host log in once.
    let quiet = no_progress();
    let (a, b) = tokio::join!(pool.connect(&db, &route, &quiet), pool.connect(&db, &route, &quiet));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a.1 && b.1);
    assert!(Arc::ptr_eq(&first, &a.0) && Arc::ptr_eq(&first, &b.0));
    let pid = |c: Arc<SshConnection>| async move { c.exec("echo $PPID", None, 64).await.unwrap().stdout_text() };
    // Same sshd session process serves both channels.
    assert_eq!(pid(first.clone()).await, pid(a.0.clone()).await);

    // Unshared routes and sharing switched off get their own connection.
    let (own, _) = pool.connect(&db, &server.route(None), &no_progress()).await.unwrap();
    assert!(!Arc::ptr_eq(&own, &first));
    pool.set_sharing(false);
    let (separate, reused) = pool.connect(&db, &route, &no_progress()).await.unwrap();
    assert!(!reused && !Arc::ptr_eq(&separate, &first));
    pool.set_sharing(true);

    // Once every user is gone the connection closes; the next connect logs in again.
    let weak = Arc::downgrade(&first);
    drop((first, a, b));
    assert!(weak.upgrade().is_none());
    let (again, reused) = pool.connect(&db, &route, &no_progress()).await.unwrap();
    assert!(!reused);
    drop(again);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn sftp_falls_back_to_its_own_connection_at_max_sessions() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let pool = ConnectionPool::new();
    let sftp = crate::sftp::SftpManager::new();
    // One more SFTP session than sshd's MaxSessions (10) allows per connection.
    for i in 0..11 {
        sftp.connect(db.clone(), &pool, format!("s{i}"), "host".into(), server.route(Some("max-sessions")))
            .await
            .unwrap_or_else(|e| panic!("session {i}: {e}"));
    }
    for i in 0..11 {
        assert!(!sftp.list(&format!("s{i}"), "/").await.unwrap().is_empty());
        sftp.disconnect(&format!("s{i}")).await.unwrap();
    }
}

async fn install_key(connection: &SshConnection, home: &str, key: &str) -> conn::ExecOutput {
    let command = format!("HOME={home} {}", conn::sh_command(conn::INSTALL_PUBLIC_KEY_SCRIPT));
    connection.exec(&command, Some(format!("{key}\n").as_bytes()), 4096).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn installing_a_public_key_like_ssh_copy_id() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let pool = ConnectionPool::new();
    let (connection, _) = pool.connect(&db, &server.route(None), &no_progress()).await.unwrap();
    // A throwaway HOME on the server: the real ~/.ssh is never touched.
    let home = format!("{}/termimus-install-key-{}", server.dir, uuid::Uuid::new_v4());
    let run = |command: String| {
        let connection = connection.clone();
        async move { connection.exec(&command, None, 65536).await.unwrap().stdout_text() }
    };

    // An existing file whose last line has no newline.
    run(format!("mkdir -p {home}/.ssh && printf 'ssh-ed25519 AAAAexisting old' > {home}/.ssh/authorized_keys")).await;
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMGaPL16Ro3wQhyfr7/wRktUu2x3VOrtX/SB106K/QP8 me@laptop";
    let added = install_key(&connection, &home, key).await;
    assert_eq!((added.stdout_text().trim(), added.exit_status), ("added", Some(0)), "{}", added.stderr_text());
    assert_eq!(
        run(format!("cat {home}/.ssh/authorized_keys")).await,
        format!("ssh-ed25519 AAAAexisting old\n{key}\n")
    );
    // Same key with another comment: already there.
    let again = install_key(&connection, &home, &key.replace("me@laptop", "other")).await;
    assert_eq!(again.stdout_text().trim(), "already");
    assert_eq!(install_key(&connection, &home, "garbage").await.exit_status, Some(2));

    // A fresh account: private permissions.
    let fresh = format!("{home}/fresh");
    run(format!("mkdir -p {fresh}")).await;
    assert_eq!(install_key(&connection, &fresh, key).await.stdout_text().trim(), "added");
    assert_eq!(
        run(format!("stat -c %a {fresh}/.ssh {fresh}/.ssh/authorized_keys")).await.split_whitespace().collect::<Vec<_>>(),
        ["700", "600"]
    );
    run(format!("rm -rf {home}")).await;
}

/// What a terminal's channel sees before it ends: (exit status, EOF or CLOSE seen).
async fn channel_ending(channel: &mut Channel<Msg>) -> (Option<u32>, bool) {
    let (mut status, mut ended) = (None, false);
    let wait = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => ended = true,
                _ => {}
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(20), wait).await;
    (status, ended)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn exit_and_lost_connections_look_different() {
    let server = TestServer::from_env();
    let db = Arc::new(Database::in_memory().unwrap());
    let pool = ConnectionPool::new();

    // `exit`: an exit status (and EOF/CLOSE) before the channel ends.
    let (connection, _) = pool.connect(&db, &server.route(None), &no_progress()).await.unwrap();
    let mut shell = connection.open_session().await.unwrap();
    shell.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    shell.request_shell(true).await.unwrap();
    shell.data(&b"exit 3\n"[..]).await.unwrap();
    assert_eq!(channel_ending(&mut shell).await, (Some(3), true));

    // The server side dies (its per-connection sshd is killed): the channel
    // just ends, with no exit status or EOF — the session counts as lost.
    let (connection, _) = pool.connect(&db, &server.route(None), &no_progress()).await.unwrap();
    let mut shell = connection.open_session().await.unwrap();
    shell.request_pty(true, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    shell.request_shell(true).await.unwrap();
    let killer = connection.clone();
    tokio::spawn(async move {
        let _ = killer.exec("kill -9 $PPID", None, 64).await;
    });
    assert_eq!(channel_ending(&mut shell).await, (None, false));
    assert!(connection.is_closed());
}
