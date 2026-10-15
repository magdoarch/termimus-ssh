import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";

/**
 * Copy text to the system clipboard. The Tauri clipboard plugin is the primary
 * path because WebKitGTK may reject `navigator.clipboard` without a per-origin
 * permission; the web API is the fallback.
 */
export async function copyText(text: string): Promise<void> {
  try {
    await writeText(text);
  } catch {
    await navigator.clipboard.writeText(text);
  }
}

async function readClipboardText(): Promise<string> {
  try {
    return await readText();
  } catch {
    return navigator.clipboard.readText();
  }
}

/**
 * Copy a secret (e.g. a private key) and wipe it from the clipboard after
 * `clearAfterMs`, unless the user has copied something else in the meantime.
 */
export async function copySecret(text: string, clearAfterMs = 30_000): Promise<void> {
  await copyText(text);
  setTimeout(async () => {
    try {
      if ((await readClipboardText()) === text) {
        await copyText("");
      }
    } catch {
      // Clipboard unavailable; nothing to clear
    }
  }, clearAfterMs);
}
