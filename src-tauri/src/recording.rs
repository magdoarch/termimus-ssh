//! Terminal session recordings in the asciinema v2 format (`.cast`): a JSON
//! header line, then one `[seconds, "o", text]` line per output chunk and
//! `[seconds, "r", "COLSxROWS"]` per resize. Only what the server sends is
//! recorded, never keystrokes, so typed passwords stay out of it. Files are
//! private to the user (0600 in a 0700 directory).

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Output is written to disk when more arrives this long after the last
/// write, when the buffer fills, and when the recording ends.
const FLUSH_EVERY: Duration = Duration::from_secs(2);
/// Largest recording the player loads.
pub const MAX_PLAYBACK_BYTES: u64 = 64 * 1024 * 1024;

pub fn recordings_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("termimus")
        .join("recordings")
}

pub struct Recorder {
    writer: BufWriter<File>,
    started: Instant,
    last_flush: Instant,
    /// The start of a UTF-8 character split across output chunks.
    carry: Vec<u8>,
    pub name: String,
}

impl Recorder {
    pub fn create(dir: &Path, title: &str, cols: u32, rows: u32) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        restrict(dir, 0o700);
        let now = chrono::Local::now();
        let slug: String = title
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
            .take(40)
            .collect();
        let base = format!("{}-{}", now.format("%Y%m%d-%H%M%S"), slug.trim_matches('_'));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        // Tabs reconnecting or reopening together start in the same second.
        let mut attempt = 1;
        let (file, name) = loop {
            let name = if attempt == 1 { format!("{base}.cast") } else { format!("{base}-{attempt}.cast") };
            match options.open(dir.join(&name)) {
                Ok(file) => break (file, name),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 1000 => attempt += 1,
                Err(e) => return Err(e),
            }
        };
        let mut writer = BufWriter::new(file);
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": now.timestamp(),
            "title": title,
            "env": { "TERM": "xterm-256color" },
        });
        writeln!(writer, "{header}")?;
        let started = Instant::now();
        Ok(Recorder { writer, started, last_flush: started, carry: Vec::new(), name })
    }

    fn event(&mut self, kind: &str, data: &str) {
        let at = self.started.elapsed().as_secs_f64();
        let line = serde_json::json!([(at * 1_000_000.0).round() / 1_000_000.0, kind, data]);
        let _ = writeln!(self.writer, "{line}");
        if self.last_flush.elapsed() >= FLUSH_EVERY {
            let _ = self.writer.flush();
            self.last_flush = Instant::now();
        }
    }

    pub fn output(&mut self, data: &[u8]) {
        let mut bytes = std::mem::take(&mut self.carry);
        bytes.extend_from_slice(data);
        let mut text = String::with_capacity(bytes.len());
        let mut rest = &bytes[..];
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    text.push_str(valid);
                    break;
                }
                Err(e) => {
                    let (valid, after) = rest.split_at(e.valid_up_to());
                    text.push_str(std::str::from_utf8(valid).unwrap_or_default());
                    match e.error_len() {
                        // Cut off at the end: wait for the rest.
                        None => {
                            self.carry = after.to_vec();
                            break;
                        }
                        Some(len) => {
                            text.push('\u{FFFD}');
                            rest = &after[len..];
                        }
                    }
                }
            }
        }
        if !text.is_empty() {
            self.event("o", &text);
        }
    }

    pub fn resize(&mut self, cols: u32, rows: u32) {
        self.event("r", &format!("{cols}x{rows}"));
    }

    pub fn finish(mut self) {
        let _ = self.writer.flush();
    }
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingInfo {
    pub name: String,
    pub title: String,
    /// Unix seconds.
    pub started_at: i64,
    pub duration_secs: f64,
    pub size_bytes: u64,
    pub cols: u32,
    pub rows: u32,
}

/// A recording's path, for names as `list` returns them only.
pub fn path_of(dir: &Path, name: &str) -> Result<PathBuf, String> {
    let ok = name.ends_with(".cast")
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        return Err(format!("'{name}' is not a recording"));
    }
    Ok(dir.join(name))
}

fn info(path: &Path) -> Option<RecordingInfo> {
    let file = File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    let mut header = String::new();
    BufReader::new(&file).read_line(&mut header).ok()?;
    let header: serde_json::Value = serde_json::from_str(&header).ok()?;
    // The duration is the time of the last event: read the file's tail. It
    // may start inside a UTF-8 character (box drawing is common in output).
    let mut bytes = Vec::new();
    let mut file = file;
    file.seek(SeekFrom::Start(size.saturating_sub(64 * 1024))).ok()?;
    file.take(64 * 1024).read_to_end(&mut bytes).ok();
    let tail = String::from_utf8_lossy(&bytes);
    let duration = tail
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|event| event.get(0)?.as_f64())
        .unwrap_or_default();
    Some(RecordingInfo {
        name: path.file_name()?.to_string_lossy().into_owned(),
        title: header.get("title").and_then(|t| t.as_str()).unwrap_or_default().to_string(),
        started_at: header.get("timestamp").and_then(|t| t.as_i64()).unwrap_or_default(),
        duration_secs: duration,
        size_bytes: size,
        cols: header.get("width").and_then(|w| w.as_u64()).unwrap_or(80) as u32,
        rows: header.get("height").and_then(|h| h.as_u64()).unwrap_or(24) as u32,
    })
}

/// Newest first.
pub fn list(dir: &Path) -> Vec<RecordingInfo> {
    let mut recordings: Vec<RecordingInfo> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "cast"))
        .filter_map(|path| info(&path))
        .collect();
    recordings.sort_by(|a, b| b.name.cmp(&a.name));
    recordings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_cast_file_and_lists_it() {
        let dir = std::env::temp_dir().join(format!("termimus-rec-{}", uuid::Uuid::new_v4()));
        let mut recorder = Recorder::create(&dir, "root@web 1", 100, 30).unwrap();
        recorder.output(b"hello ");
        // "é" (0xC3 0xA9) split across two chunks stays one character.
        recorder.output(&[b'c', b'a', b'f', 0xC3]);
        recorder.output(&[0xA9, b'\n', 0xFF]);
        recorder.resize(120, 40);
        let name = recorder.name.clone();
        recorder.finish();

        let text = fs::read_to_string(dir.join(&name)).unwrap();
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines[0]["version"], 2);
        assert_eq!((lines[0]["width"].as_u64(), lines[0]["height"].as_u64()), (Some(100), Some(30)));
        assert_eq!(lines[1][1], "o");
        let output: String = lines[1..].iter().filter(|e| e[1] == "o").map(|e| e[2].as_str().unwrap()).collect();
        assert_eq!(output, "hello café\n\u{FFFD}");
        assert_eq!(lines.last().unwrap()[1], "r");
        assert_eq!(lines.last().unwrap()[2], "120x40");
        assert!(name.ends_with("-root_web_1.cast"), "{name}");

        // A second recording in the same second gets its own file.
        let second = Recorder::create(&dir, "root@web 1", 100, 30).unwrap();
        assert_ne!(second.name, name);
        let second_name = second.name.clone();
        second.finish();
        fs::remove_file(dir.join(second_name)).unwrap();

        let listed = list(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!((listed[0].title.as_str(), listed[0].cols, listed[0].rows), ("root@web 1", 100, 30));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(dir.join(&name)).unwrap().permissions().mode() & 0o777, 0o600);
        }

        assert!(path_of(&dir, &name).is_ok());
        assert!(path_of(&dir, "../secret.cast").is_err());
        assert!(path_of(&dir, "notes.txt").is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
