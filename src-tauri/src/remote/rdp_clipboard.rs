//! Text clipboard for RDP over the CLIPRDR static virtual channel.
//!
//! - Remote → local: when the server announces a copy that includes
//!   CF_UNICODETEXT, the text is requested right away and handed to the
//!   frontend (`remote-clipboard-{id}`), like VNC's cut text.
//! - Local → remote: the frontend sends text (toolbar "Clipboard" button);
//!   it is announced to the server and served when the remote side pastes.
//!
//! CLIPRDR callbacks run inside IronRDP's channel processing, so they can't
//! touch the session directly; they queue `ClipboardEvent`s that the session
//! loop in `rdp.rs` turns into PDUs or frontend events.

use std::sync::{Arc, Mutex};

use ironrdp_cliprdr::backend::{ClipboardMessage, CliprdrBackend};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use tokio::sync::mpsc;

/// Largest remote clipboard text forwarded to the frontend.
const MAX_REMOTE_TEXT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum ClipboardEvent {
    /// A CLIPRDR action the session loop must encode and send.
    Message(ClipboardMessage),
    /// Text copied on the remote machine.
    RemoteText(String),
}

#[derive(Debug)]
pub struct ClipboardBridge {
    events: mpsc::UnboundedSender<ClipboardEvent>,
    /// Text currently offered to the server, if any.
    local_text: Arc<Mutex<Option<String>>>,
}

ironrdp_core::impl_as_any!(ClipboardBridge);

impl ClipboardBridge {
    pub fn new(
        events: mpsc::UnboundedSender<ClipboardEvent>,
        local_text: Arc<Mutex<Option<String>>>,
    ) -> Self {
        Self { events, local_text }
    }

    fn send(&self, message: ClipboardMessage) {
        let _ = self.events.send(ClipboardEvent::Message(message));
    }

    fn has_local_text(&self) -> bool {
        self.local_text.lock().map(|t| t.is_some()).unwrap_or(false)
    }
}

pub fn unicode_text_format() -> ClipboardFormat {
    ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)
}

impl CliprdrBackend for ClipboardBridge {
    fn temporary_directory(&self) -> &str {
        // File transfer isn't supported.
        ""
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {
        // The server expects our format list after initialization; offer
        // text only if the user already sent some.
        let formats = if self.has_local_text() { vec![unicode_text_format()] } else { Vec::new() };
        self.send(ClipboardMessage::SendInitiateCopy(formats));
    }

    fn on_process_negotiated_capabilities(&mut self, _capabilities: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        if available_formats.iter().any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT) {
            self.send(ClipboardMessage::SendInitiatePaste(ClipboardFormatId::CF_UNICODETEXT));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let text = self.local_text.lock().ok().and_then(|t| t.clone());
        let response = match text {
            Some(text) if request.format == ClipboardFormatId::CF_UNICODETEXT => {
                FormatDataResponse::new_unicode_string(&text)
            }
            _ => FormatDataResponse::new_error(),
        };
        self.send(ClipboardMessage::SendFormatData(response));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() || response.data().len() > MAX_REMOTE_TEXT_BYTES {
            return;
        }
        if let Ok(text) = response.to_unicode_string() {
            let text = text.trim_end_matches('\0').to_string();
            if !text.is_empty() {
                let _ = self.events.send(ClipboardEvent::RemoteText(text));
            }
        }
    }

    // File transfer and clipboard locking aren't supported.
    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(text: Option<&str>) -> (ClipboardBridge, mpsc::UnboundedReceiver<ClipboardEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (ClipboardBridge::new(tx, Arc::new(Mutex::new(text.map(String::from)))), rx)
    }

    #[test]
    fn remote_text_copy_requests_unicode_text() {
        let (mut b, mut rx) = bridge(None);
        b.on_remote_copy(&[unicode_text_format()]);
        assert!(matches!(
            rx.try_recv(),
            Ok(ClipboardEvent::Message(ClipboardMessage::SendInitiatePaste(f))) if f == ClipboardFormatId::CF_UNICODETEXT
        ));
    }

    #[test]
    fn format_data_response_becomes_remote_text() {
        let (mut b, mut rx) = bridge(None);
        b.on_format_data_response(FormatDataResponse::new_unicode_string("halo ✓"));
        assert!(matches!(rx.try_recv(), Ok(ClipboardEvent::RemoteText(t)) if t == "halo ✓"));
    }

    #[test]
    fn serves_local_text_or_error() {
        let (mut b, mut rx) = bridge(Some("dari lokal"));
        b.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
        match rx.try_recv() {
            Ok(ClipboardEvent::Message(ClipboardMessage::SendFormatData(r))) => {
                assert_eq!(r.to_unicode_string().unwrap().trim_end_matches('\0'), "dari lokal");
            }
            other => panic!("unexpected {other:?}"),
        }

        let (mut b, mut rx) = bridge(None);
        b.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
        assert!(matches!(
            rx.try_recv(),
            Ok(ClipboardEvent::Message(ClipboardMessage::SendFormatData(r))) if r.is_error()
        ));
    }

    #[test]
    fn format_list_offers_text_only_when_present() {
        let (mut b, mut rx) = bridge(None);
        b.on_request_format_list();
        assert!(matches!(rx.try_recv(), Ok(ClipboardEvent::Message(ClipboardMessage::SendInitiateCopy(f))) if f.is_empty()));
        let (mut b, mut rx) = bridge(Some("x"));
        b.on_request_format_list();
        assert!(matches!(rx.try_recv(), Ok(ClipboardEvent::Message(ClipboardMessage::SendInitiateCopy(f))) if f.len() == 1));
    }
}
