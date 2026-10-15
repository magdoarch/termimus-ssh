//! Binary wire format for remote desktop frames sent to the frontend over a
//! `tauri::ipc::Channel` (raw bytes, not JSON).
//!
//! A message is a sequence of ops, all integers little-endian:
//!
//! | op | layout                                              |
//! |----|-----------------------------------------------------|
//! | 1  | RESIZE `w:u16 h:u16`                                |
//! | 2  | RAW    `x y w h:u16  len:u32  RGBA bytes`           |
//! | 3  | COPY   `x y w h:u16  src_x src_y:u16`               |
//! | 4  | JPEG   `x y w h:u16  len:u32  JPEG bytes`           |
//!
//! Must stay in sync with `src/lib/remoteFrame.ts`.

pub const OP_RESIZE: u8 = 1;
pub const OP_RAW: u8 = 2;
pub const OP_COPY: u8 = 3;
pub const OP_JPEG: u8 = 4;

#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// Accumulates ops between two flushes to the frontend.
#[derive(Default)]
pub struct FrameBatch {
    buf: Vec<u8>,
}

impl FrameBatch {
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn resize(&mut self, width: u16, height: u16) {
        self.buf.push(OP_RESIZE);
        self.push_u16(width);
        self.push_u16(height);
    }

    /// `rgbx` is 4 bytes per pixel (R, G, B, unused). The unused byte is set
    /// to 255 so the frontend can hand the bytes straight to `ImageData`.
    /// Returns false (and writes nothing) if the size doesn't match the rect.
    pub fn raw(&mut self, rect: Rect, mut rgbx: Vec<u8>) -> bool {
        let expected = rect.width as usize * rect.height as usize * 4;
        if rgbx.len() != expected {
            return false;
        }
        for alpha in rgbx.iter_mut().skip(3).step_by(4) {
            *alpha = 255;
        }
        self.buf.push(OP_RAW);
        self.push_rect(rect);
        self.push_u32(rgbx.len() as u32);
        self.buf.extend_from_slice(&rgbx);
        true
    }

    pub fn copy(&mut self, dst: Rect, src_x: u16, src_y: u16) {
        self.buf.push(OP_COPY);
        self.push_rect(dst);
        self.push_u16(src_x);
        self.push_u16(src_y);
    }

    pub fn jpeg(&mut self, rect: Rect, jpeg: &[u8]) {
        self.buf.push(OP_JPEG);
        self.push_rect(rect);
        self.push_u32(jpeg.len() as u32);
        self.buf.extend_from_slice(jpeg);
    }

    fn push_rect(&mut self, rect: Rect) {
        self.push_u16(rect.x);
        self.push_u16(rect.y);
        self.push_u16(rect.width);
        self.push_u16(rect.height);
    }

    fn push_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_sets_alpha_and_encodes_header() {
        let mut batch = FrameBatch::default();
        let rect = Rect { x: 1, y: 2, width: 1, height: 2 };
        assert!(batch.raw(rect, vec![10, 20, 30, 0, 40, 50, 60, 0]));
        let bytes = batch.take();
        assert_eq!(bytes[0], OP_RAW);
        assert_eq!(&bytes[1..9], &[1, 0, 2, 0, 1, 0, 2, 0]);
        assert_eq!(&bytes[9..13], &8u32.to_le_bytes());
        assert_eq!(&bytes[13..], &[10, 20, 30, 255, 40, 50, 60, 255]);
    }

    #[test]
    fn raw_rejects_mismatched_size() {
        let mut batch = FrameBatch::default();
        let rect = Rect { x: 0, y: 0, width: 2, height: 2 };
        assert!(!batch.raw(rect, vec![0; 4]));
        assert!(batch.is_empty());
    }
}
