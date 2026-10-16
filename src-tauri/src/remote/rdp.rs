//! RDP client built on IronRDP.
//!
//! Connection: X.224 negotiation → TLS upgrade → server key TOFU check →
//! CredSSP/NLA (or plain TLS when the server doesn't offer NLA) → active
//! session. Dirty regions of the decoded desktop are streamed to the frontend
//! with the same binary frame format as VNC (`frame.rs`).
//!
//! `ironrdp-tls` accepts any server certificate (RDP servers are almost always
//! self-signed), so the server's TLS public key is pinned in `known_hosts`
//! here, Trust-On-First-Use, the same way SSH host keys are.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ironrdp_cliprdr::backend::ClipboardMessage;
use ironrdp_cliprdr::CliprdrClient;

use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::{ClientConnector, ConnectionResult, Credentials, DesktopSize, ServerName};
use ironrdp_core::WriteBuf;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::rdp::capability_sets::{client_codecs_capabilities, MajorPlatformType};
use ironrdp_pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{fast_path, ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{single_sequence_step_read, split_tokio_framed, FramedWrite, TokioFramed};
use sha2::{Digest, Sha256};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::frame::{FrameBatch, Rect};
use super::input::RemoteInput;
use super::rdp_clipboard::{unicode_text_format, ClipboardBridge, ClipboardEvent};
use crate::db::models::KnownHost;
use crate::db::Database;

/// Same pacing as VNC: flush dirty regions to the frontend at most ~60 fps.
const FRAME_INTERVAL: Duration = Duration::from_millis(16);

/// Beyond this many separate dirty rects per flush, send their bounding box
/// instead (one big copy beats many tiny IPC ops).
const MAX_RECTS_PER_FLUSH: usize = 16;

/// Key type recorded in `known_hosts` for pinned RDP TLS keys.
pub const RDP_KEY_TYPE: &str = "rdp-tls";

/// How often CLIPRDR lock timeouts are driven.
const CLIPBOARD_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

/// One wheel notch in RDP rotation units.
const WHEEL_NOTCH: i16 = 120;

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}
type UpgradedFramed = TokioFramed<Box<dyn AsyncReadWrite + Unpin + Send + Sync>>;

pub struct RdpLogin {
    pub username: String,
    pub password: Option<Zeroizing<String>>,
    pub domain: Option<String>,
}

pub struct RdpConnection {
    framed: UpgradedFramed,
    result: ConnectionResult,
    clipboard_rx: mpsc::UnboundedReceiver<ClipboardEvent>,
    /// Text offered to the server by the CLIPRDR bridge.
    local_clipboard: Arc<Mutex<Option<String>>>,
}

impl RdpConnection {
    pub fn desktop_size(&self) -> (u16, u16) {
        (self.result.desktop_size.width, self.result.desktop_size.height)
    }
}

/// Clamp a requested desktop size to what RDP servers accept (even width,
/// 200..=8192 per side).
pub fn sanitize_desktop_size(width: u16, height: u16) -> (u16, u16) {
    let width = width.clamp(200, 8192) & !1;
    let height = height.clamp(200, 8192);
    (width, height)
}

fn build_config(login: &RdpLogin, width: u16, height: u16) -> Result<ironrdp_connector::Config, String> {
    let codecs = client_codecs_capabilities(&[]).map_err(|e| format!("RDP codec setup failed: {e}"))?;
    Ok(ironrdp_connector::Config {
        credentials: Credentials::UsernamePassword {
            username: login.username.clone(),
            password: login.password.as_deref().map(|p| p.to_string()).unwrap_or_default(),
        },
        domain: login.domain.clone().filter(|d| !d.trim().is_empty()),
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width, height },
        desktop_scale_factor: 0,
        bitmap: Some(ironrdp_connector::BitmapConfig {
            color_depth: 32,
            lossy_compression: true,
            codecs,
        }),
        client_build: 0,
        client_name: "Termimus".to_string(),
        client_dir: String::new(),
        platform: MajorPlatformType::UNSPECIFIED,
        hardware_id: None,
        license_cache: None,
        // Let IronRDP draw the remote cursor into the framebuffer.
        enable_server_pointer: true,
        pointer_software_rendering: true,
        autologon: false,
        enable_audio_playback: false,
        request_data: None,
        multitransport_flags: None,
        compression_type: Some(CompressionType::K64),
        performance_flags: PerformanceFlags::default(),
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    })
}

/// Negotiate, upgrade to TLS, verify the server key and authenticate.
/// `progress(step, step_name, message)` mirrors the SSH connect stages.
pub async fn connect<S>(
    stream: S,
    db: Arc<Database>,
    address: &str,
    port: u16,
    login: RdpLogin,
    desktop: (u16, u16),
    progress: impl Fn(u8, &str, &str),
) -> Result<RdpConnection, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let (width, height) = sanitize_desktop_size(desktop.0, desktop.1);
    let config = build_config(&login, width, height)?;
    // The stream may be tunneled through a jump host, so there is no
    // meaningful local socket address to report.
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut connector = ClientConnector::new(config, client_addr);
    let (clipboard_tx, clipboard_rx) = mpsc::unbounded_channel();
    let local_clipboard = Arc::new(Mutex::new(None));
    connector.attach_static_channel(CliprdrClient::new(Box::new(ClipboardBridge::new(
        clipboard_tx,
        local_clipboard.clone(),
    ))));
    let mut framed = TokioFramed::new(stream);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| format!("RDP negotiation failed: {}", describe_connector_error(&e)))?;

    progress(2, "host_key", "TLS handshake and server certificate check (Trust On First Use)...");
    let (initial_stream, leftover) = framed.into_inner();
    let (tls_stream, cert) = ironrdp_tls::upgrade(initial_stream, address)
        .await
        .map_err(|e| format!("TLS handshake with the RDP server failed: {e}"))?;
    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&cert)
        .ok_or_else(|| "Could not read the RDP server's TLS public key".to_string())?
        .to_owned();
    verify_server_key(&db, address, port, &server_public_key)?;

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let erased: Box<dyn AsyncReadWrite + Unpin + Send + Sync> = Box::new(tls_stream);
    let mut framed = TokioFramed::new_with_leftover(erased, leftover);

    progress(3, "authenticating", &format!("Authenticating as {}...", login.username));
    let result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut ReqwestNetworkClient::new(),
        ServerName::new(address),
        server_public_key,
        None,
    )
    .await
    .map_err(|e| format!("RDP login failed: {}", describe_connector_error(&e)))?;

    Ok(RdpConnection {
        framed,
        result,
        clipboard_rx,
        local_clipboard,
    })
}

fn describe_connector_error(e: &ironrdp_connector::ConnectorError) -> String {
    // The Display impl only shows the context; the source carries the cause
    // (e.g. CredSSP "logon failure").
    let mut message = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

pub fn key_fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("SHA256:{}", hex.join(""))
}

/// Trust-On-First-Use for the server's TLS key, shared with SSH's known_hosts
/// table (key_type "rdp-tls"). Fails closed on DB errors and on mismatch.
fn verify_server_key(db: &Database, address: &str, port: u16, public_key: &[u8]) -> Result<(), String> {
    let fingerprint = key_fingerprint(public_key);
    let now = chrono::Utc::now().to_rfc3339();
    let existing = db
        .get_known_host(address, port)
        .map_err(|e| format!("Could not read known hosts to verify the server key: {e}"))?;
    match existing {
        None => db
            .save_known_host(&KnownHost {
                address: address.to_string(),
                port,
                key_type: RDP_KEY_TYPE.to_string(),
                fingerprint,
                first_seen_at: now.clone(),
                last_seen_at: now,
            })
            .map_err(|e| format!("Could not save the server key to known hosts: {e}")),
        Some(mut known) if known.fingerprint == fingerprint => {
            known.last_seen_at = now;
            let _ = db.save_known_host(&known);
            Ok(())
        }
        Some(known) => Err(format!(
            "REMOTE HOST IDENTIFICATION HAS CHANGED for {address}:{port}! The RDP server presented a TLS key \
             with fingerprint {fingerprint} but the previously trusted key was {} (first trusted {}). This could \
             indicate a man-in-the-middle attack, or the server certificate was regenerated. Remove the old entry \
             from Known Hosts if you trust this change.",
            known.fingerprint, known.first_seen_at
        )),
    }
}

/// Translate frontend input into IronRDP input operations.
fn to_operations(input: RemoteInput) -> Vec<Operation> {
    match input {
        RemoteInput::Key { keysym, down, scancode } => {
            if let Some(code) = scancode {
                let scancode = Scancode::from_u16(code);
                vec![if down { Operation::KeyPressed(scancode) } else { Operation::KeyReleased(scancode) }]
            } else if let Some(ch) = char::from_u32(keysym_to_unicode(keysym)).filter(|c| !c.is_control()) {
                // No physical key (e.g. a dead-key composition): send the character.
                vec![if down { Operation::UnicodeKeyPressed(ch) } else { Operation::UnicodeKeyReleased(ch) }]
            } else {
                Vec::new()
            }
        }
        RemoteInput::Pointer { x, y, buttons } => {
            let mut ops = vec![Operation::MouseMove(MousePosition { x, y })];
            for (bit, button) in [(1u8, MouseButton::Left), (2, MouseButton::Middle), (4, MouseButton::Right)] {
                // The input database only emits events for actual state changes.
                ops.push(if buttons & bit != 0 {
                    Operation::MouseButtonPressed(button)
                } else {
                    Operation::MouseButtonReleased(button)
                });
            }
            let wheel = |is_vertical, rotation_units| Operation::WheelRotations(WheelRotations { is_vertical, rotation_units });
            if buttons & (1 << 3) != 0 {
                ops.push(wheel(true, WHEEL_NOTCH));
            }
            if buttons & (1 << 4) != 0 {
                ops.push(wheel(true, -WHEEL_NOTCH));
            }
            if buttons & (1 << 5) != 0 {
                ops.push(wheel(false, -WHEEL_NOTCH));
            }
            if buttons & (1 << 6) != 0 {
                ops.push(wheel(false, WHEEL_NOTCH));
            }
            ops
        }
        // Clipboard text goes through CLIPRDR in `run`, not as input events; a
        // refresh has no RDP equivalent the server must honor.
        RemoteInput::Clipboard { .. } | RemoteInput::Refresh => Vec::new(),
    }
}

/// Latin-1 keysyms are their code point; Unicode keysyms are 0x01000000 + cp.
fn keysym_to_unicode(keysym: u32) -> u32 {
    if keysym & 0xff00_0000 == 0x0100_0000 {
        keysym & 0x00ff_ffff
    } else if keysym <= 0xff {
        keysym
    } else {
        0
    }
}

fn to_rect(r: &InclusiveRectangle) -> Rect {
    Rect {
        x: r.left,
        y: r.top,
        width: r.right.saturating_sub(r.left) + 1,
        height: r.bottom.saturating_sub(r.top) + 1,
    }
}

/// Copy a region of the decoded RGBA desktop into the batch.
fn push_region(batch: &mut FrameBatch, image: &DecodedImage, rect: Rect) {
    let (img_w, img_h) = (image.width(), image.height());
    if rect.x >= img_w || rect.y >= img_h {
        return;
    }
    let rect = Rect {
        width: rect.width.min(img_w - rect.x),
        height: rect.height.min(img_h - rect.y),
        ..rect
    };
    if rect.width == 0 || rect.height == 0 {
        return;
    }
    let stride = image.stride();
    let row_bytes = rect.width as usize * 4;
    let data = image.data();
    let mut pixels = Vec::with_capacity(row_bytes * rect.height as usize);
    for row in 0..rect.height as usize {
        let start = (rect.y as usize + row) * stride + rect.x as usize * 4;
        pixels.extend_from_slice(&data[start..start + row_bytes]);
    }
    batch.raw(rect, pixels);
}

fn flush_dirty(
    dirty: &mut Vec<Rect>,
    image: &DecodedImage,
    batch: &mut FrameBatch,
    on_frame: &Channel<InvokeResponseBody>,
) -> Result<(), String> {
    if dirty.len() > MAX_RECTS_PER_FLUSH {
        let x = dirty.iter().map(|r| r.x).min().unwrap_or(0);
        let y = dirty.iter().map(|r| r.y).min().unwrap_or(0);
        let right = dirty.iter().map(|r| r.x + r.width).max().unwrap_or(0);
        let bottom = dirty.iter().map(|r| r.y + r.height).max().unwrap_or(0);
        push_region(batch, image, Rect { x, y, width: right - x, height: bottom - y });
    } else {
        for rect in dirty.iter() {
            push_region(batch, image, *rect);
        }
    }
    dirty.clear();
    if batch.is_empty() {
        return Ok(());
    }
    on_frame
        .send(InvokeResponseBody::Raw(batch.take()))
        .map_err(|e| format!("Frontend frame channel closed: {e}"))
}

/// Encode a CLIPRDR action queued by the clipboard bridge.
fn clipboard_frames(stage: &mut ActiveStage, message: ClipboardMessage) -> Result<Vec<ActiveStageOutput>, String> {
    let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else {
        return Ok(Vec::new());
    };
    let messages = match message {
        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats),
        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format),
        ClipboardMessage::SendFormatData(response) => cliprdr.submit_format_data(response),
        // File transfer isn't supported; backend errors need no reply.
        _ => return Ok(Vec::new()),
    }
    .map_err(|e| format!("RDP clipboard error: {e}"))?;
    let frame = stage
        .process_svc_processor_messages(messages)
        .map_err(|e| format!("RDP clipboard error: {e}"))?;
    Ok(vec![ActiveStageOutput::ResponseFrame(frame)])
}

/// Run the active session until the server ends it or the input channel
/// closes (user disconnect).
pub async fn run(
    connection: RdpConnection,
    mut input_rx: mpsc::UnboundedReceiver<RemoteInput>,
    on_frame: &Channel<InvokeResponseBody>,
    app: &AppHandle,
    session_id: &str,
    view_only: bool,
) -> Result<(), String> {
    let RdpConnection {
        framed,
        result,
        mut clipboard_rx,
        local_clipboard,
    } = connection;
    let clipboard_event = format!("remote-clipboard-{session_id}");
    let mut clipboard_cleanup = tokio::time::interval(CLIPBOARD_CLEANUP_INTERVAL);
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let desktop = result.desktop_size;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, desktop.width, desktop.height);
    let activation_factory = result.activation_factory;
    let mut stage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();
    let mut input_db = ironrdp_input::Database::new();

    let mut batch = FrameBatch::default();
    batch.resize(desktop.width, desktop.height);
    let mut dirty: Vec<Rect> = Vec::new();
    let mut tick = tokio::time::interval(FRAME_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => {
                let (action, payload) = match frame {
                    Ok(f) => f,
                    // Server closed the connection.
                    Err(_) => return Ok(()),
                };
                stage
                    .process(&mut image, action, &payload)
                    .map_err(|e| format!("RDP session error: {e}"))?
            }
            input = input_rx.recv() => match input {
                // Session removed (user disconnected): say goodbye properly.
                None => {
                    if let Ok(outputs) = stage.graceful_shutdown() {
                        for out in outputs {
                            if let ActiveStageOutput::ResponseFrame(frame) = out {
                                let _ = writer.write_all(&frame).await;
                            }
                        }
                    }
                    return Ok(());
                }
                Some(input) if view_only && input.is_interactive() => Vec::new(),
                Some(RemoteInput::Clipboard { text }) => {
                    // Offer the text; the server requests it when the remote side pastes.
                    if let Ok(mut offered) = local_clipboard.lock() {
                        *offered = Some(text);
                    }
                    clipboard_frames(&mut stage, ClipboardMessage::SendInitiateCopy(vec![unicode_text_format()]))?
                }
                Some(input) => {
                    let ops = to_operations(input);
                    if ops.is_empty() {
                        Vec::new()
                    } else {
                        let events = input_db.apply(ops);
                        stage
                            .process_fastpath_input(&mut image, &events)
                            .map_err(|e| format!("RDP input error: {e}"))?
                    }
                }
            },
            Some(event) = clipboard_rx.recv() => match event {
                ClipboardEvent::Message(message) => clipboard_frames(&mut stage, message)?,
                ClipboardEvent::RemoteText(text) => {
                    let _ = app.emit(&clipboard_event, text);
                    Vec::new()
                }
            },
            _ = clipboard_cleanup.tick() => match stage.get_svc_processor_mut::<CliprdrClient>() {
                Some(cliprdr) => match cliprdr.drive_timeouts() {
                    Ok(messages) => {
                        let frame = stage
                            .process_svc_processor_messages(messages)
                            .map_err(|e| format!("RDP clipboard error: {e}"))?;
                        if frame.is_empty() { Vec::new() } else { vec![ActiveStageOutput::ResponseFrame(frame)] }
                    }
                    Err(_) => Vec::new(),
                },
                None => Vec::new(),
            },
            _ = tick.tick() => {
                flush_dirty(&mut dirty, &image, &mut batch, on_frame)?;
                Vec::new()
            }
        };

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => writer
                    .write_all(&frame)
                    .await
                    .map_err(|e| format!("RDP connection lost: {e}"))?,
                ActiveStageOutput::GraphicsUpdate(region) => dirty.push(to_rect(&region)),
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation Sequence (e.g. after a server-side resize).
                    let mut activation = activation_factory.create();
                    let mut buf = WriteBuf::new();
                    loop {
                        let written = single_sequence_step_read(&mut reader, &mut activation, &mut buf)
                            .await
                            .map_err(|e| format!("RDP reactivation failed: {}", describe_connector_error(&e)))?;
                        if written.size().is_some() {
                            writer
                                .write_all(buf.filled())
                                .await
                                .map_err(|e| format!("RDP connection lost: {e}"))?;
                        }
                        if let ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            enable_server_pointer,
                            pointer_software_rendering,
                        } = activation.connection_activation_state()
                        {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: activation.io_channel_id(),
                                    user_channel_id: activation.user_channel_id(),
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    bulk_decompressor: None,
                                }
                                .build(),
                            );
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            dirty.clear();
                            batch.resize(desktop_size.width, desktop_size.height);
                            break;
                        }
                    }
                }
                ActiveStageOutput::Terminate(_reason) => {
                    flush_dirty(&mut dirty, &image, &mut batch, on_frame)?;
                    return Ok(());
                }
                // Pointer updates are rendered into the framebuffer (software
                // pointer); multitransport and auto-detect aren't used.
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_size_is_clamped_and_even() {
        assert_eq!(sanitize_desktop_size(1001, 700), (1000, 700));
        assert_eq!(sanitize_desktop_size(10, 10), (200, 200));
        assert_eq!(sanitize_desktop_size(20000, 9000), (8192, 8192));
    }

    #[test]
    fn inclusive_rect_converts_to_size() {
        let r = to_rect(&InclusiveRectangle { left: 10, top: 20, right: 19, bottom: 20 });
        assert_eq!((r.x, r.y, r.width, r.height), (10, 20, 10, 1));
    }

    #[test]
    fn pointer_input_maps_buttons_and_wheel() {
        let ops = to_operations(RemoteInput::Pointer { x: 5, y: 6, buttons: 1 | (1 << 3) });
        assert!(matches!(ops[0], Operation::MouseMove(MousePosition { x: 5, y: 6 })));
        assert!(matches!(ops[1], Operation::MouseButtonPressed(MouseButton::Left)));
        assert!(matches!(ops[2], Operation::MouseButtonReleased(MouseButton::Middle)));
        assert!(ops.iter().any(|o| matches!(o, Operation::WheelRotations(w) if w.is_vertical && w.rotation_units == 120)));
    }

    #[test]
    fn key_input_prefers_scancode() {
        let ops = to_operations(RemoteInput::Key { keysym: 0x61, down: true, scancode: Some(0x1E) });
        assert!(matches!(ops[0], Operation::KeyPressed(_)));
        let ops = to_operations(RemoteInput::Key { keysym: 0x01000000 + 0x00e9, down: true, scancode: None });
        assert!(matches!(ops[0], Operation::UnicodeKeyPressed('é')));
    }

    /// Manual integration test against a real RDP server (e.g. xrdp or Windows):
    ///   RDP_TEST_ADDR=127.0.0.1:3389 RDP_TEST_USER=me RDP_TEST_PASSWORD=secret \
    ///     cargo test -- --ignored rdp_connect
    /// Uses a throwaway known_hosts DB under a temp XDG_CONFIG_HOME.
    #[tokio::test]
    #[ignore]
    async fn rdp_connect_and_login() {
        let addr = std::env::var("RDP_TEST_ADDR").expect("RDP_TEST_ADDR");
        let (host, port) = addr.rsplit_once(':').expect("host:port");
        let port: u16 = port.parse().unwrap();
        let config_home = std::env::temp_dir().join(format!("termimus-rdp-test-{}", std::process::id()));
        std::env::set_var("XDG_CONFIG_HOME", &config_home);
        let db = Arc::new(Database::new().unwrap());

        let login = || RdpLogin {
            username: std::env::var("RDP_TEST_USER").expect("RDP_TEST_USER"),
            password: std::env::var("RDP_TEST_PASSWORD").ok().map(Zeroizing::new),
            domain: None,
        };
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let conn = connect(tcp, db.clone(), host, port, login(), (1024, 768), |_, _, _| {})
            .await
            .unwrap();
        let (w, h) = conn.desktop_size();
        assert!(w > 0 && h > 0);

        // The key was pinned on first use; a second connect must match it.
        let pinned = db.get_known_host(host, port).unwrap().expect("key pinned");
        assert_eq!(pinned.key_type, RDP_KEY_TYPE);
        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        connect(tcp, db, host, port, login(), (1024, 768), |_, _, _| {}).await.unwrap();
        let _ = std::fs::remove_dir_all(config_home);
    }

    #[test]
    fn fingerprint_is_stable_hex() {
        let fp = key_fingerprint(b"abc");
        assert_eq!(fp, "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
