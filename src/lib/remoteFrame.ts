/**
 * Decoder for the binary frame batches streamed by the backend remote desktop
 * sessions. Wire format (little-endian) — keep in sync with
 * src-tauri/src/remote/frame.rs:
 *
 *   1 RESIZE  w:u16 h:u16
 *   2 RAW     x y w h:u16  len:u32  RGBA bytes
 *   3 COPY    x y w h:u16  srcX srcY:u16
 *   4 JPEG    x y w h:u16  len:u32  JPEG bytes
 */

const OP_RESIZE = 1;
const OP_RAW = 2;
const OP_COPY = 3;
const OP_JPEG = 4;

export interface RemoteSurface {
  canvas: HTMLCanvasElement;
  ctx: CanvasRenderingContext2D;
  /** Called after the remote framebuffer size changes */
  onResize?: (width: number, height: number) => void;
}

export function createRemoteSurface(onResize?: (width: number, height: number) => void): RemoteSurface {
  const canvas = document.createElement("canvas");
  canvas.width = 1;
  canvas.height = 1;
  const ctx = canvas.getContext("2d", { alpha: false });
  if (!ctx) throw new Error("Canvas 2D context unavailable");
  return { canvas, ctx, onResize };
}

/**
 * Draw one batch. Ops are applied strictly in order (JPEG decoding is awaited)
 * so later rects never get overwritten by an earlier, slower one; callers
 * should chain batches on a promise for the same reason.
 */
export async function applyFrameBatch(surface: RemoteSurface, buffer: ArrayBuffer): Promise<void> {
  const view = new DataView(buffer);
  const { canvas, ctx } = surface;
  let off = 0;

  const u16 = () => {
    const v = view.getUint16(off, true);
    off += 2;
    return v;
  };
  const u32 = () => {
    const v = view.getUint32(off, true);
    off += 4;
    return v;
  };

  while (off < buffer.byteLength) {
    const op = view.getUint8(off);
    off += 1;

    if (op === OP_RESIZE) {
      const width = u16();
      const height = u16();
      if (width > 0 && height > 0 && (canvas.width !== width || canvas.height !== height)) {
        canvas.width = width;
        canvas.height = height;
        surface.onResize?.(width, height);
      }
      continue;
    }

    const x = u16();
    const y = u16();
    const w = u16();
    const h = u16();

    if (op === OP_RAW) {
      const len = u32();
      if (w > 0 && h > 0 && len === w * h * 4) {
        const pixels = new Uint8ClampedArray(buffer, off, len);
        ctx.putImageData(new ImageData(pixels, w, h), x, y);
      }
      off += len;
    } else if (op === OP_COPY) {
      const srcX = u16();
      const srcY = u16();
      if (w > 0 && h > 0) {
        ctx.drawImage(canvas, srcX, srcY, w, h, x, y, w, h);
      }
    } else if (op === OP_JPEG) {
      const len = u32();
      const jpeg = new Blob([new Uint8Array(buffer, off, len)], { type: "image/jpeg" });
      off += len;
      try {
        const bitmap = await createImageBitmap(jpeg);
        ctx.drawImage(bitmap, x, y, w, h);
        bitmap.close();
      } catch {
        // A corrupt tile only leaves a stale rect; the next update repaints it.
      }
    } else {
      // Unknown op: the rest of the batch can't be parsed safely.
      console.warn(`[remote] unknown frame op ${op}, dropping rest of batch`);
      return;
    }
  }
}
