//! VNC (RFB) client built on `vnc-rs`.
//!
//! `vnc-rs` only implements the "None" and "VNC Authentication" security
//! types (no VeNCrypt/TLS, no Apple ARD), and RFB itself is unencrypted —
//! which is why routing through an SSH jump host is the recommended setup.

use std::time::Duration;

use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use vnc::{PixelFormat, VncClient, VncConnector, VncEncoding, VncError, VncEvent, X11Event};
use zeroize::Zeroizing;

use super::frame::{FrameBatch, Rect};
use super::input::{to_latin1_lossy, RemoteInput};

/// How often pending server events are flushed to the frontend and the next
/// incremental update is requested (~60 fps upper bound).
const FRAME_INTERVAL: Duration = Duration::from_millis(16);

/// Flush mid-drain once a batch gets this big, so a burst of full-screen
/// updates doesn't turn into one huge IPC message.
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

pub async fn handshake<S>(
    stream: S,
    password: Option<Zeroizing<String>>,
    shared: bool,
) -> Result<VncClient, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    VncConnector::new(stream)
        .set_auth_method(async move {
            password
                .map(|p| p.to_string())
                .ok_or(VncError::NoPassword)
        })
        .add_encoding(VncEncoding::Tight)
        .add_encoding(VncEncoding::Zrle)
        .add_encoding(VncEncoding::CopyRect)
        .add_encoding(VncEncoding::Raw)
        .allow_shared(shared)
        .set_pixel_format(PixelFormat::rgba())
        .build()
        .map_err(describe_error)?
        .try_start()
        .await
        .map_err(describe_error)?
        .finish()
        .map_err(describe_error)
}

/// Pump frames to the frontend and input to the server until either side
/// goes away. Returns `Ok` when the session ended normally (server closed,
/// user disconnected) and `Err` with a reason otherwise.
pub async fn run(
    client: &VncClient,
    mut input_rx: mpsc::UnboundedReceiver<RemoteInput>,
    on_frame: &Channel<InvokeResponseBody>,
    app: &AppHandle,
    session_id: &str,
    view_only: bool,
) -> Result<(), String> {
    let clipboard_event = format!("remote-clipboard-{session_id}");
    let mut tick = tokio::time::interval(FRAME_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut batch = FrameBatch::default();

    loop {
        tokio::select! {
            input = input_rx.recv() => {
                // Channel closed: the session was removed (user disconnected).
                let Some(input) = input else { return Ok(()) };
                if view_only && input.is_interactive() {
                    continue;
                }
                let event = match input {
                    RemoteInput::Key { keysym, down } => X11Event::KeyEvent((keysym, down).into()),
                    RemoteInput::Pointer { x, y, buttons } => X11Event::PointerEvent((x, y, buttons).into()),
                    RemoteInput::Clipboard { text } => X11Event::CopyText(to_latin1_lossy(&text)),
                    RemoteInput::Refresh => X11Event::FullRefresh,
                };
                if client.input(event).await.is_err() {
                    return Ok(());
                }
            }
            _ = tick.tick() => {
                loop {
                    // poll_event, not recv_event: vnc-rs holds its client lock
                    // while recv_event waits, which would block input().
                    match client.poll_event().await {
                        Ok(Some(event)) => {
                            handle_event(event, &mut batch, app, &clipboard_event)?;
                            if batch.len() >= MAX_BATCH_BYTES {
                                send(on_frame, &mut batch)?;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            send(on_frame, &mut batch)?;
                            return Ok(());
                        }
                    }
                }
                send(on_frame, &mut batch)?;
                if client.input(X11Event::Refresh).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

fn handle_event(
    event: VncEvent,
    batch: &mut FrameBatch,
    app: &AppHandle,
    clipboard_event: &str,
) -> Result<(), String> {
    match event {
        VncEvent::SetResolution(screen) => batch.resize(screen.width, screen.height),
        VncEvent::RawImage(rect, data) => {
            batch.raw(to_rect(rect), data);
        }
        VncEvent::Copy(dst, src) => batch.copy(to_rect(dst), src.x, src.y),
        VncEvent::JpegImage(rect, data) => batch.jpeg(to_rect(rect), &data),
        VncEvent::Text(text) => {
            let _ = app.emit(clipboard_event, text);
        }
        VncEvent::Error(message) => return Err(message),
        // Cursor pseudo-encoding isn't requested (the server draws the
        // cursor into the framebuffer); bell and pixel-format notices need
        // no action.
        _ => {}
    }
    Ok(())
}

fn send(on_frame: &Channel<InvokeResponseBody>, batch: &mut FrameBatch) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    on_frame
        .send(InvokeResponseBody::Raw(batch.take()))
        .map_err(|e| format!("Frontend frame channel closed: {e}"))
}

fn to_rect(rect: vnc::Rect) -> Rect {
    Rect {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
    }
}

fn describe_error(e: VncError) -> String {
    match e {
        VncError::NoPassword => "The VNC server requires a password, but none is configured for this host".to_string(),
        VncError::WrongPassword => "VNC authentication failed: wrong password".to_string(),
        // The server's own reason, e.g. x11vnc's "password check failed!"
        VncError::General(reason) => format!("VNC server rejected the connection: {reason}"),
        VncError::InvalidSecurityTyep(_) | VncError::ConnectError => format!(
            "{e}. Termimus supports VNC servers using no authentication or classic VNC password \
             authentication (e.g. TigerVNC with SecurityTypes=VncAuth)."
        ),
        other => format!("VNC error: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Manual integration test against a real server, e.g.:
    ///   Xvfb :99 -screen 0 1024x768x24 &
    ///   x11vnc -display :99 -rfbport 5999 -passwd secret &
    ///   VNC_TEST_ADDR=127.0.0.1:5999 VNC_TEST_PASSWORD=secret cargo test -- --ignored vnc
    #[tokio::test]
    #[ignore]
    async fn vnc_handshake_and_first_frame() {
        let addr = std::env::var("VNC_TEST_ADDR").expect("VNC_TEST_ADDR");
        let password = std::env::var("VNC_TEST_PASSWORD").ok().map(Zeroizing::new);
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let client = handshake(tcp, password, true).await.unwrap();

        let mut batch = FrameBatch::default();
        let mut got_resolution = false;
        let mut got_image = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !(got_resolution && got_image) {
            match client.poll_event().await.unwrap() {
                Some(VncEvent::SetResolution(s)) => {
                    assert!(s.width > 0 && s.height > 0);
                    got_resolution = true;
                }
                Some(VncEvent::RawImage(rect, data)) => {
                    assert!(batch.raw(to_rect(rect), data), "RGBA size must match rect");
                    got_image = true;
                }
                Some(VncEvent::JpegImage(..)) | Some(VncEvent::Copy(..)) => got_image = true,
                Some(_) => {}
                None => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        assert!(got_resolution, "no SetResolution from server");
        assert!(got_image, "no framebuffer update from server");

        client.input(X11Event::PointerEvent((10, 10, 1).into())).await.unwrap();
        client.input(X11Event::PointerEvent((10, 10, 0).into())).await.unwrap();
        client.input(X11Event::KeyEvent((0x61, true).into())).await.unwrap();
        client.input(X11Event::KeyEvent((0x61, false).into())).await.unwrap();
        client.close().await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn vnc_wrong_password_is_rejected() {
        let addr = std::env::var("VNC_TEST_ADDR").expect("VNC_TEST_ADDR");
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let err = handshake(tcp, Some(Zeroizing::new("definitely-wrong".into())), true)
            .await
            .err()
            .expect("handshake must fail");
        assert!(err.contains("rejected") || err.contains("wrong password"), "unexpected error: {err}");
    }
}
