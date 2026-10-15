//! Login flows with keyboard-interactive (2FA) against an in-process russh
//! server that behaves like common sshd setups.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth};
use russh::{MethodKind, MethodSet};
use tokio::net::{TcpListener, TcpStream};

use super::auth_prompt::{AuthPromptRequest, AuthPrompter};
use super::*;

const OTP: &str = "123456";

/// What the test server asks for, sshd-style.
#[derive(Clone, Default)]
struct ServerPolicy {
    /// Asked in the keyboard-interactive round (`Password: `, hidden).
    password: Option<&'static str>,
    /// Asked in the keyboard-interactive round (`Verification code: `, echoed).
    otp: Option<&'static str>,
    /// Accepted as a first factor; keyboard-interactive must follow
    /// (`AuthenticationMethods publickey,keyboard-interactive`).
    first_factor_key: Option<PublicKey>,
}

struct TestServer {
    policy: ServerPolicy,
}

fn only_keyboard_interactive() -> Option<MethodSet> {
    Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..]))
}

impl server::Handler for TestServer {
    type Error = anyhow::Error;

    // The plain password method is disabled (PasswordAuthentication no);
    // passwords are only taken through keyboard-interactive (PAM).
    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject { proceed_with_methods: only_keyboard_interactive() })
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        if self.policy.first_factor_key.as_ref() == Some(key) {
            // First factor done; the client must continue with keyboard-interactive.
            Ok(Auth::Reject { proceed_with_methods: only_keyboard_interactive() })
        } else {
            Ok(Auth::Reject { proceed_with_methods: None })
        }
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let mut prompts: Vec<(Cow<'static, str>, bool)> = Vec::new();
        let mut expected: Vec<&str> = Vec::new();
        if let Some(password) = self.policy.password {
            prompts.push(("Password: ".into(), false));
            expected.push(password);
        }
        if let Some(otp) = self.policy.otp {
            prompts.push(("Verification code: ".into(), true));
            expected.push(otp);
        }
        if prompts.is_empty() {
            // Nothing configured to ask: keyboard-interactive isn't a way in.
            return Ok(Auth::Reject { proceed_with_methods: None });
        }
        match response {
            None => Ok(Auth::Partial {
                name: "Two-factor authentication".into(),
                instructions: "".into(),
                prompts: prompts.into(),
            }),
            Some(response) => {
                let answers: Vec<String> = response.map(|b| String::from_utf8_lossy(&b).into_owned()).collect();
                if answers == expected {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::Reject { proceed_with_methods: None })
                }
            }
        }
    }
}

async fn spawn_server(policy: ServerPolicy) -> u16 {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap()],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let handler = TestServer { policy: policy.clone() };
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    port
}

/// Answers every prompt with a fixed reply and records what was asked.
struct ScriptedUser {
    reply: Option<Vec<String>>,
    asked: Mutex<Vec<AuthPromptRequest>>,
}

impl ScriptedUser {
    fn answering(reply: Option<&[&str]>) -> Self {
        Self {
            reply: reply.map(|r| r.iter().map(|s| s.to_string()).collect()),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn asked_prompts(&self) -> Vec<Vec<(String, bool)>> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.prompts.iter().map(|p| (p.prompt.clone(), p.echo)).collect())
            .collect()
    }
}

impl AuthPrompter for ScriptedUser {
    async fn ask(&self, request: AuthPromptRequest) -> Option<Vec<String>> {
        self.asked.lock().unwrap().push(request);
        self.reply.clone()
    }
}

async fn login(port: u16, auth: SshAuth, user: &ScriptedUser) -> Result<bool, String> {
    let handler = SshClientHandler {
        address: "127.0.0.1".into(),
        port,
        db: Arc::new(Database::in_memory().unwrap()),
        forwarded_tcpip: None,
    };
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut handle = client::connect_stream(default_client_config(), tcp, handler).await.unwrap();
    authenticate_with(&mut handle, "alice", &auth, "alice@test", user).await
}

fn password(p: &str) -> SshAuth {
    SshAuth::Password(p.to_string())
}

#[tokio::test]
async fn stored_password_fills_pam_password_and_user_enters_otp() {
    let port = spawn_server(ServerPolicy { password: Some("pw"), otp: Some(OTP), ..Default::default() }).await;
    let user = ScriptedUser::answering(Some(&[OTP]));
    assert_eq!(login(port, password("pw"), &user).await, Ok(true));
    // Only the code was asked; the stored password answered "Password:".
    assert_eq!(user.asked_prompts(), vec![vec![("Verification code: ".to_string(), true)]]);
}

#[tokio::test]
async fn password_only_through_keyboard_interactive_needs_no_dialog() {
    let port = spawn_server(ServerPolicy { password: Some("pw"), ..Default::default() }).await;
    let user = ScriptedUser::answering(None);
    assert_eq!(login(port, password("pw"), &user).await, Ok(true));
    assert!(user.asked_prompts().is_empty());
}

#[tokio::test]
async fn key_then_otp() {
    let key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
    let port = spawn_server(ServerPolicy {
        otp: Some(OTP),
        first_factor_key: Some(key.public_key().clone()),
        ..Default::default()
    })
    .await;
    let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
    let user = ScriptedUser::answering(Some(&[OTP]));
    let auth = SshAuth::PrivateKey { pem, passphrase: None };
    assert_eq!(login(port, auth, &user).await, Ok(true));
    assert_eq!(user.asked_prompts().len(), 1);
}

#[tokio::test]
async fn wrong_code_is_rejected() {
    let port = spawn_server(ServerPolicy { password: Some("pw"), otp: Some(OTP), ..Default::default() }).await;
    let user = ScriptedUser::answering(Some(&["000000"]));
    assert_eq!(login(port, password("pw"), &user).await, Ok(false));
}

#[tokio::test]
async fn cancelling_the_prompt_fails_the_login() {
    let port = spawn_server(ServerPolicy { otp: Some(OTP), ..Default::default() }).await;
    let user = ScriptedUser::answering(None);
    assert_eq!(login(port, password("pw"), &user).await, Err("Authentication cancelled".to_string()));
}

#[tokio::test]
async fn unknown_key_without_keyboard_interactive_is_rejected() {
    // Not a 2FA server: rejected keys must not end up in a prompt.
    let port = spawn_server(ServerPolicy::default()).await;
    let key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
    let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
    let user = ScriptedUser::answering(Some(&[OTP]));
    assert_eq!(login(port, SshAuth::PrivateKey { pem, passphrase: None }, &user).await, Ok(false));
    assert!(user.asked_prompts().is_empty());
}
