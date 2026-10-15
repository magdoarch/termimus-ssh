//! Keyboard-interactive authentication prompts (2FA / OTP codes, Duo, PAM
//! questions) answered by the user through the UI.
//!
//! The backend emits `ssh-auth-prompt` and waits for `ssh_auth_prompt_respond`;
//! a prompt that isn't answered in time is withdrawn with
//! `ssh-auth-prompt-closed`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// sshd's default LoginGraceTime: the server gives up after this anyway.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize)]
pub struct PromptField {
    pub prompt: String,
    /// Whether the answer may be shown while typing (codes) or must be
    /// hidden (passwords).
    pub echo: bool,
}

/// One round of questions from the server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPromptRequest {
    /// Who is asking, e.g. "root@10.0.0.5".
    pub target: String,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<PromptField>,
}

/// Answers keyboard-interactive prompts; `None` cancels the login.
pub trait AuthPrompter: Send + Sync {
    fn ask(&self, request: AuthPromptRequest) -> impl Future<Output = Option<Vec<String>>> + Send;
}

struct Broker {
    app: AppHandle,
    pending: Mutex<HashMap<String, oneshot::Sender<Option<Vec<String>>>>>,
}

static BROKER: OnceLock<Broker> = OnceLock::new();

/// Enable UI prompts; called once at app startup. Without it (e.g. in tests)
/// [`UiPrompter`] cancels every prompt.
pub fn init(app: AppHandle) {
    let _ = BROKER.set(Broker {
        app,
        pending: Mutex::new(HashMap::new()),
    });
}

/// Deliver the user's answers (`None` = cancel). Returns false when the
/// prompt is no longer waiting (answered elsewhere or timed out).
pub fn respond(request_id: &str, answers: Option<Vec<String>>) -> bool {
    let Some(broker) = BROKER.get() else { return false };
    let sender = broker.pending.lock().ok().and_then(|mut p| p.remove(request_id));
    sender.is_some_and(|tx| tx.send(answers).is_ok())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PromptEvent {
    request_id: String,
    #[serde(flatten)]
    request: AuthPromptRequest,
}

/// Asks through the app UI.
pub struct UiPrompter;

impl AuthPrompter for UiPrompter {
    async fn ask(&self, request: AuthPromptRequest) -> Option<Vec<String>> {
        let broker = BROKER.get()?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        broker.pending.lock().ok()?.insert(request_id.clone(), tx);
        let _ = broker.app.emit(
            "ssh-auth-prompt",
            PromptEvent {
                request_id: request_id.clone(),
                request,
            },
        );

        let answer = tokio::time::timeout(PROMPT_TIMEOUT, rx).await;
        if let Ok(mut pending) = broker.pending.lock() {
            pending.remove(&request_id);
        }
        match answer {
            Ok(Ok(answers)) => answers,
            // Timed out (or dropped): take the dialog down.
            _ => {
                let _ = broker.app.emit("ssh-auth-prompt-closed", &request_id);
                None
            }
        }
    }
}

pub fn is_password_prompt(prompt: &str) -> bool {
    prompt.to_lowercase().contains("password")
}

/// Fill what we can without asking: the stored password goes into the first
/// hidden "password" prompt, once per login (a repeated password prompt means
/// it was wrong, so the user is asked instead). Returns the pre-filled answers
/// and the indices of the prompts the user must answer.
pub fn plan_answers(prompts: &[PromptField], stored_password: &mut Option<Zeroizing<String>>) -> (Vec<Option<String>>, Vec<usize>) {
    let mut answers: Vec<Option<String>> = vec![None; prompts.len()];
    if let Some(index) = prompts.iter().position(|p| !p.echo && is_password_prompt(&p.prompt)) {
        if let Some(password) = stored_password.take() {
            answers[index] = Some(password.to_string());
        }
    }
    let ask = (0..prompts.len()).filter(|&i| answers[i].is_none()).collect();
    (answers, ask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(prompt: &str, echo: bool) -> PromptField {
        PromptField { prompt: prompt.into(), echo }
    }

    #[test]
    fn stored_password_fills_password_prompt_once() {
        let prompts = [field("Password: ", false), field("Verification code: ", true)];
        let mut stored = Some(Zeroizing::new("s3cret".to_string()));
        let (answers, ask) = plan_answers(&prompts, &mut stored);
        assert_eq!(answers[0].as_deref(), Some("s3cret"));
        assert_eq!(ask, vec![1]);
        assert!(stored.is_none());

        // PAM asks again (wrong password): now the user answers.
        let (answers, ask) = plan_answers(&prompts[..1], &mut stored);
        assert_eq!(answers, vec![None]);
        assert_eq!(ask, vec![0]);
    }

    #[test]
    fn otp_and_visible_prompts_are_asked() {
        let mut stored = Some(Zeroizing::new("pw".to_string()));
        // An echoed prompt mentioning "password" is not a password field.
        let prompts = [field("Duo passcode or option (1-2): ", true), field("Password hint (visible): ", true)];
        let (answers, ask) = plan_answers(&prompts, &mut stored);
        assert!(answers.iter().all(Option::is_none));
        assert_eq!(ask, vec![0, 1]);
        assert!(stored.is_some(), "password kept for a later round");
    }
}
