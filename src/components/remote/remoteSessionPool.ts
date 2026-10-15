import { Channel } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { api, RemoteInputEvent } from "../../lib/api";
import { copyText } from "../../lib/clipboard";
import { applyFrameBatch, createRemoteSurface, RemoteSurface } from "../../lib/remoteFrame";
import { keysymForEvent, rfbButtonMask, rfbWheelBit, scancodeForEvent } from "../../lib/remoteInput";
import { useSessionStore } from "../../stores/useSessionStore";
import type { ConnectionLog } from "../terminal/ConnectionProgress";

interface ProgressPayload {
  step: number;
  step_name: string;
  message: string;
  timestamp: string;
  is_error: boolean;
}

export interface RemoteConnectionState {
  status: "connecting" | "connected" | "closed";
  logs: ConnectionLog[];
  step: number;
  error: string | null;
}

export type RemoteScaleMode = "fit" | "actual";

/** A key as both protocols need it: keysym for VNC, scancode for RDP. */
export interface RemoteKey {
  keysym: number;
  scancode?: number;
}

export interface RemoteSessionEntry {
  sessionId: string;
  hostId: string;
  surface: RemoteSurface;
  /** Persistent element holding the canvas; re-parented on remount */
  element: HTMLDivElement;
  state: RemoteConnectionState;
  scaleMode: RemoteScaleMode;
  /** Mounted views to notify when state or remote size changes */
  listeners: Set<() => void>;
  unlistenFns: Array<() => void>;
  /** Serializes batch drawing so async JPEG tiles keep their order */
  drawQueue: Promise<void>;
  pendingInput: RemoteInputEvent[];
  inputFlushScheduled: boolean;
  /** Key sent on keydown per physical key, so keyup releases the same one */
  pressedKeys: Map<string, RemoteKey>;
  /** First connect happens once the view is mounted and has a size */
  started: boolean;
  pointerButtons: number;
  disposed: boolean;
}

// Module-level pool (like terminalPool in XtermView) so a VNC session and its
// framebuffer survive splits, drags and tab switches without reconnecting.
const remotePool = new Map<string, RemoteSessionEntry>();

function notify(entry: RemoteSessionEntry) {
  entry.listeners.forEach((fn) => fn());
}

function setState(entry: RemoteSessionEntry, patch: Partial<RemoteConnectionState>) {
  entry.state = { ...entry.state, ...patch };
  notify(entry);
}

export function getRemoteSession(sessionId: string): RemoteSessionEntry | undefined {
  return remotePool.get(sessionId);
}

export function getOrCreateRemoteSession(sessionId: string, hostId: string): RemoteSessionEntry {
  const existing = remotePool.get(sessionId);
  if (existing) return existing;

  const element = document.createElement("div");
  element.tabIndex = 0;
  element.className = "remote-desktop-surface";
  element.style.cssText =
    "position:absolute;inset:0;display:flex;align-items:center;justify-content:center;overflow:hidden;outline:none;";

  const entry: RemoteSessionEntry = {
    sessionId,
    hostId,
    surface: createRemoteSurface(() => notify(entry)),
    element,
    state: { status: "connecting", logs: [], step: 1, error: null },
    scaleMode: "fit",
    listeners: new Set(),
    unlistenFns: [],
    drawQueue: Promise.resolve(),
    pendingInput: [],
    inputFlushScheduled: false,
    pressedKeys: new Map(),
    pointerButtons: 0,
    disposed: false,
    started: false,
  };
  element.appendChild(entry.surface.canvas);
  applyScaleMode(entry);
  attachInputHandlers(entry);
  remotePool.set(sessionId, entry);

  // listen() resolves asynchronously; unlisten right away if the tab was
  // closed in the meantime instead of leaking the listener.
  const keep = (unlisten: () => void) => {
    if (entry.disposed) unlisten();
    else entry.unlistenFns.push(unlisten);
  };

  listen<ProgressPayload>(`remote-progress-${sessionId}`, (event) => {
    const p = event.payload;
    const log: ConnectionLog = {
      step: p.step,
      message: p.message,
      timestamp: p.timestamp,
      isError: p.is_error,
    };
    setState(entry, {
      step: p.step,
      logs: [...entry.state.logs, log],
      ...(p.is_error ? { error: p.message } : {}),
    });
  }).then(keep);

  listen<string | null>(`remote-closed-${sessionId}`, (event) => {
    useSessionStore.getState().setSessionConnected(sessionId, false);
    setState(entry, {
      status: "closed",
      error: event.payload ? `Session ended: ${event.payload}` : "The remote desktop session was closed",
    });
  }).then(keep);

  listen<string>(`remote-clipboard-${sessionId}`, (event) => {
    copyText(event.payload).catch(() => {});
  }).then(keep);

  return entry;
}

/** Connect for the first time; called by the view once it is mounted, so the
 *  RDP desktop can be sized to the pane. */
export function startRemoteSession(entry: RemoteSessionEntry) {
  if (entry.started || entry.disposed) return;
  entry.started = true;
  connectRemoteSession(entry);
}

/** (Re)connect. A fresh Channel per attempt: message indices restart per backend channel. */
export function connectRemoteSession(entry: RemoteSessionEntry) {
  const host = useSessionStore.getState().tabs.find((t) => t.id === entry.sessionId);
  setState(entry, {
    status: "connecting",
    step: 1,
    error: null,
    logs: [
      {
        step: 1,
        message: `Initiating ${(host?.protocol ?? "vnc").toUpperCase()} connection to ${host?.hostAddress || "server"}...`,
        timestamp: new Date().toISOString(),
        isError: false,
      },
    ],
  });

  const channel = new Channel<ArrayBuffer>();
  channel.onmessage = (buffer) => {
    if (entry.disposed) return;
    entry.drawQueue = entry.drawQueue
      .then(() => applyFrameBatch(entry.surface, buffer))
      .catch((e) => console.error("[remote] failed to draw frame:", e));
  };

  api
    .remoteConnect(entry.hostId, entry.sessionId, channel, paneSize(entry))
    .then(() => {
      if (entry.disposed) return;
      useSessionStore.getState().setSessionConnected(entry.sessionId, true);
      setState(entry, { status: "connected", step: 5, error: null });
      entry.element.focus();
    })
    .catch((e) => {
      if (entry.disposed) return;
      const message = String(e);
      useSessionStore.getState().setSessionError(entry.sessionId, message);
      setState(entry, { status: "closed", error: message });
    });
}

/** Pane size in CSS pixels, used as the RDP desktop size (VNC ignores it). */
function paneSize(entry: RemoteSessionEntry): { width: number; height: number } | undefined {
  const rect = entry.element.getBoundingClientRect();
  if (rect.width < 100 || rect.height < 100) return undefined;
  return { width: Math.round(rect.width), height: Math.round(rect.height) };
}

export function disposeRemoteSession(sessionId: string) {
  const entry = remotePool.get(sessionId);
  if (!entry) return;
  entry.disposed = true;
  entry.unlistenFns.forEach((fn) => {
    try {
      fn();
    } catch {
      // ignore
    }
  });
  entry.listeners.clear();
  entry.element.remove();
  remotePool.delete(sessionId);
}

export function setRemoteScaleMode(entry: RemoteSessionEntry, mode: RemoteScaleMode) {
  entry.scaleMode = mode;
  applyScaleMode(entry);
  notify(entry);
}

function applyScaleMode(entry: RemoteSessionEntry) {
  const { canvas } = entry.surface;
  if (entry.scaleMode === "fit") {
    // Shrink to fit, keeping the aspect ratio; the element box then equals the
    // drawn image, so pointer mapping can use getBoundingClientRect.
    entry.element.style.overflow = "hidden";
    entry.element.style.alignItems = "center";
    entry.element.style.justifyContent = "center";
    canvas.style.cssText = "max-width:100%;max-height:100%;width:auto;height:auto;display:block;";
  } else {
    entry.element.style.overflow = "auto";
    entry.element.style.alignItems = "flex-start";
    entry.element.style.justifyContent = "flex-start";
    canvas.style.cssText = "max-width:none;max-height:none;display:block;flex-shrink:0;";
  }
}

// ── Input ────────────────────────────────────────────────────────────────

export function sendRemoteInput(entry: RemoteSessionEntry, event: RemoteInputEvent) {
  if (entry.state.status !== "connected") return;
  const last = entry.pendingInput[entry.pendingInput.length - 1];
  // Coalesce consecutive moves with the same buttons into the latest position.
  if (event.type === "pointer" && last?.type === "pointer" && last.buttons === event.buttons) {
    entry.pendingInput[entry.pendingInput.length - 1] = event;
  } else {
    entry.pendingInput.push(event);
  }
  if (!entry.inputFlushScheduled) {
    entry.inputFlushScheduled = true;
    requestAnimationFrame(() => {
      entry.inputFlushScheduled = false;
      const events = entry.pendingInput;
      entry.pendingInput = [];
      if (events.length > 0 && !entry.disposed) {
        api.remoteInput(entry.sessionId, events).catch(() => {});
      }
    });
  }
}

/** Release every key still held, e.g. when focus leaves the view mid-chord. */
export function releaseRemoteKeys(entry: RemoteSessionEntry) {
  entry.pressedKeys.forEach((key) => sendRemoteInput(entry, { type: "key", ...key, down: false }));
  entry.pressedKeys.clear();
}

export function sendRemoteKeyCombo(entry: RemoteSessionEntry, keys: RemoteKey[]) {
  keys.forEach((key) => sendRemoteInput(entry, { type: "key", ...key, down: true }));
  [...keys].reverse().forEach((key) => sendRemoteInput(entry, { type: "key", ...key, down: false }));
}

function remotePosition(entry: RemoteSessionEntry, event: MouseEvent): { x: number; y: number } {
  const { canvas } = entry.surface;
  const rect = canvas.getBoundingClientRect();
  const scaleX = rect.width > 0 ? canvas.width / rect.width : 1;
  const scaleY = rect.height > 0 ? canvas.height / rect.height : 1;
  const x = Math.round((event.clientX - rect.left) * scaleX);
  const y = Math.round((event.clientY - rect.top) * scaleY);
  return {
    x: Math.min(Math.max(x, 0), canvas.width - 1),
    y: Math.min(Math.max(y, 0), canvas.height - 1),
  };
}

function attachInputHandlers(entry: RemoteSessionEntry) {
  const { element } = entry;
  const canvas = entry.surface.canvas;

  const pointer = (event: PointerEvent) => {
    const { x, y } = remotePosition(entry, event);
    entry.pointerButtons = rfbButtonMask(event.buttons);
    sendRemoteInput(entry, { type: "pointer", x, y, buttons: entry.pointerButtons });
  };
  canvas.addEventListener("pointermove", pointer);
  canvas.addEventListener("pointerdown", (event) => {
    element.focus();
    canvas.setPointerCapture(event.pointerId);
    pointer(event);
  });
  canvas.addEventListener("pointerup", pointer);
  canvas.addEventListener("contextmenu", (event) => event.preventDefault());
  canvas.addEventListener(
    "wheel",
    (event) => {
      event.preventDefault();
      const bit = rfbWheelBit(event);
      if (!bit) return;
      const { x, y } = remotePosition(entry, event);
      sendRemoteInput(entry, { type: "pointer", x, y, buttons: entry.pointerButtons | bit });
      sendRemoteInput(entry, { type: "pointer", x, y, buttons: entry.pointerButtons });
    },
    { passive: false }
  );

  // Keyboard goes to the remote machine while the view has focus: stop the
  // app's own shortcuts (bubble-phase window listeners) from seeing it.
  element.addEventListener("keydown", (event) => {
    event.preventDefault();
    event.stopPropagation();
    const keysym = keysymForEvent(event);
    const scancode = scancodeForEvent(event);
    if (keysym === null && scancode === undefined) return;
    const key: RemoteKey = { keysym: keysym ?? 0, scancode };
    entry.pressedKeys.set(event.code || event.key, key);
    sendRemoteInput(entry, { type: "key", ...key, down: true });
  });
  element.addEventListener("keyup", (event) => {
    event.preventDefault();
    event.stopPropagation();
    const id = event.code || event.key;
    const key = entry.pressedKeys.get(id);
    entry.pressedKeys.delete(id);
    // Only release keys we pressed (focus may have arrived mid-keystroke).
    if (key) sendRemoteInput(entry, { type: "key", ...key, down: false });
  });
  element.addEventListener("blur", () => releaseRemoteKeys(entry));
}
