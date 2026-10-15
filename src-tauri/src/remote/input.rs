use serde::Deserialize;

/// Input sent from the frontend to a remote desktop session.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RemoteInput {
    /// X11 keysym (mapped from `KeyboardEvent` in `src/lib/remoteInput.ts`).
    Key { keysym: u32, down: bool },
    /// Position in remote framebuffer pixels. `buttons` is the RFB mask:
    /// bit 0 left, 1 middle, 2 right, 3/4 wheel up/down.
    Pointer { x: u16, y: u16, buttons: u8 },
    /// Text to place on the remote clipboard.
    Clipboard { text: String },
    /// Ask the server for a full (non-incremental) frame.
    Refresh,
}

impl RemoteInput {
    /// Whether this input changes the remote machine (blocked in view-only mode).
    pub fn is_interactive(&self) -> bool {
        !matches!(self, RemoteInput::Refresh)
    }
}

/// RFB cut text is Latin-1 only; replace anything outside it.
pub fn to_latin1_lossy(text: &str) -> String {
    text.chars()
        .map(|c| if (c as u32) <= 0xFF { c } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1_replaces_wide_chars() {
        assert_eq!(to_latin1_lossy("café ✓"), "café ?");
    }

    #[test]
    fn deserializes_tagged_input() {
        let input: RemoteInput =
            serde_json::from_str(r#"{"type":"pointer","x":10,"y":20,"buttons":1}"#).unwrap();
        assert!(matches!(input, RemoteInput::Pointer { x: 10, y: 20, buttons: 1 }));
        assert!(!RemoteInput::Refresh.is_interactive());
    }
}
