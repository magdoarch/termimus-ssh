import { useEffect, useRef, useState } from "react";
import { ClipboardPaste, Expand, RefreshCw, Shrink } from "lucide-react";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { useHostStore } from "../../stores/useHostStore";
import { useSessionStore } from "../../stores/useSessionStore";
import { KEYSYM, SCANCODE } from "../../lib/remoteInput";
import { ConnectionProgress } from "../terminal/ConnectionProgress";
import {
  connectRemoteSession,
  getOrCreateRemoteSession,
  RemoteSessionEntry,
  sendRemoteInput,
  sendRemoteKeyCombo,
  setRemoteScaleMode,
  startRemoteSession,
} from "./remoteSessionPool";

interface RemoteDesktopViewProps {
  sessionId: string;
  hostId: string;
  visible: boolean;
  isFocused?: boolean;
}

export function RemoteDesktopView({ sessionId, hostId, visible, isFocused = true }: RemoteDesktopViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const host = useHostStore((s) => s.hosts.find((h) => h.id === hostId));
  const closeSession = useSessionStore((s) => s.closeSession);
  const protocol = useSessionStore((s) => s.tabs.find((t) => t.id === sessionId)?.protocol) ?? "vnc";

  // The pool entry outlives this component (split/drag remounts); create it
  // synchronously so the first render already reflects its state.
  const [entry] = useState<RemoteSessionEntry>(() => getOrCreateRemoteSession(sessionId, hostId));
  const [snapshot, setSnapshot] = useState(() => ({
    state: entry.state,
    scaleMode: entry.scaleMode,
    size: { width: entry.surface.canvas.width, height: entry.surface.canvas.height },
  }));

  useEffect(() => {
    const sync = () =>
      setSnapshot({
        state: entry.state,
        scaleMode: entry.scaleMode,
        size: { width: entry.surface.canvas.width, height: entry.surface.canvas.height },
      });
    entry.listeners.add(sync);
    sync();
    return () => {
      entry.listeners.delete(sync);
    };
  }, [entry]);

  // Re-parent the persistent surface into this mount.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    if (entry.element.parentElement !== container) container.appendChild(entry.element);
    startRemoteSession(entry);
    return () => {
      if (entry.element.parentElement === container) container.removeChild(entry.element);
    };
  }, [entry]);

  useEffect(() => {
    if (visible && isFocused && entry.state.status === "connected") entry.element.focus();
  }, [visible, isFocused, entry, snapshot.state.status]);

  const { state, scaleMode, size } = snapshot;
  const connected = state.status === "connected";

  const sendClipboard = async () => {
    try {
      const text = await readText().catch(() => navigator.clipboard.readText());
      if (text) sendRemoteInput(entry, { type: "clipboard", text });
    } catch {
      // clipboard unavailable
    }
    entry.element.focus();
  };

  const toolbarButton =
    "flex h-7 items-center gap-1.5 rounded-md px-2 text-[11px] text-[var(--text-secondary)] hover:bg-[var(--surface-high)] hover:text-[var(--text-primary)] transition-colors";

  return (
    <div
      className="absolute inset-0 bg-[var(--canvas)]"
      style={{
        visibility: visible ? "visible" : "hidden",
        pointerEvents: visible ? "auto" : "none",
        zIndex: visible ? 10 : 0,
      }}
    >
      <div ref={containerRef} className="absolute inset-0" />

      {connected && (
        <div className="group absolute top-0 left-1/2 z-20 -translate-x-1/2 pt-1">
          <div className="flex items-center gap-0.5 rounded-lg border border-[var(--border)] bg-[var(--surface-container)]/95 px-1 py-0.5 opacity-30 shadow-lg backdrop-blur-md transition-opacity group-hover:opacity-100">
            <button
              className={toolbarButton}
              title="Send Ctrl+Alt+Del"
              onClick={() => {
                sendRemoteKeyCombo(entry, [
                  { keysym: KEYSYM.ControlLeft, scancode: SCANCODE.ControlLeft },
                  { keysym: KEYSYM.AltLeft, scancode: SCANCODE.AltLeft },
                  { keysym: KEYSYM.Delete, scancode: SCANCODE.Delete },
                ]);
                entry.element.focus();
              }}
            >
              <span className="font-mono">Ctrl+Alt+Del</span>
            </button>
            {/* RDP clipboard redirection (CLIPRDR) isn't implemented yet */}
            {protocol === "vnc" && (
              <button className={toolbarButton} title="Paste local clipboard to the remote clipboard" onClick={sendClipboard}>
                <ClipboardPaste size={13} />
                <span>Clipboard</span>
              </button>
            )}
            <button
              className={toolbarButton}
              title={scaleMode === "fit" ? "Show at actual size (1:1)" : "Fit to pane"}
              onClick={() => setRemoteScaleMode(entry, scaleMode === "fit" ? "actual" : "fit")}
            >
              {scaleMode === "fit" ? <Expand size={13} /> : <Shrink size={13} />}
              <span>{scaleMode === "fit" ? "1:1" : "Fit"}</span>
            </button>
            {protocol === "vnc" && (
              <button
                className={toolbarButton}
                title="Request a full screen refresh"
                onClick={() => sendRemoteInput(entry, { type: "refresh" })}
              >
                <RefreshCw size={13} />
              </button>
            )}
            <span className="px-1.5 font-mono text-[10px] text-[var(--text-muted)]">
              {size.width}×{size.height}
            </span>
          </div>
        </div>
      )}

      {!connected && (
        <ConnectionProgress
          protocol={protocol}
          sessionId={sessionId}
          host={host}
          logs={state.logs}
          currentStep={state.step}
          error={state.error}
          onRetry={() => connectRemoteSession(entry)}
          onClose={() => closeSession(sessionId)}
        />
      )}
    </div>
  );
}
