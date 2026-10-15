import { useCallback, useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { ArrowLeft, Download, Film, LoaderCircle, Play, Trash2, X } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { api, type RecordingInfo } from "../../lib/api";
import { formatBytes, formatDate, formatDuration } from "../../lib/format";
import { useConfirmStore } from "../../stores/useConfirmStore";
import { useRecordingStore } from "../../stores/useRecordingStore";
import { RecordingPlayer } from "./RecordingPlayer";

/** Session recordings: list, play back, export (.cast) and delete. */
export function RecordingsModal() {
  const { isOpen, close } = useRecordingStore(useShallow((s) => ({ isOpen: s.isOpen, close: s.close })));
  const [recordings, setRecordings] = useState<RecordingInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [playing, setPlaying] = useState<{ info: RecordingInfo; text: string } | null>(null);
  const [loading, setLoading] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setRecordings(await api.listRecordings());
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    if (!isOpen) {
      setPlaying(null);
      return;
    }
    refresh();
  }, [isOpen, refresh]);

  useEffect(() => {
    if (!isOpen) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") close();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, close]);

  if (!isOpen) return null;

  async function play(info: RecordingInfo) {
    setLoading(info.name);
    try {
      setPlaying({ info, text: await api.readRecording(info.name) });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(null);
    }
  }

  async function exportRecording(info: RecordingInfo) {
    try {
      const destination = await save({
        defaultPath: info.name,
        filters: [{ name: "asciinema recording", extensions: ["cast"] }],
      });
      if (destination) await api.exportRecording(info.name, destination);
    } catch (e) {
      setError(String(e));
    }
  }

  function remove(info: RecordingInfo) {
    useConfirmStore.getState().confirm({
      title: "Delete recording",
      message: `Delete the recording "${info.title || info.name}"? This can't be undone.`,
      confirmLabel: "Delete",
      isDanger: true,
      onConfirm: async () => {
        await api.deleteRecording(info.name);
        await refresh();
      },
    });
  }

  return (
    <div
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) close();
      }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
    >
      <div className="flex max-h-[90vh] w-full max-w-5xl flex-col rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] shadow-2xl">
        <div className="flex items-center justify-between gap-3 border-b border-[var(--border)] px-5 py-3">
          <div className="flex min-w-0 items-center gap-2">
            {playing ? (
              <button
                type="button"
                onClick={() => setPlaying(null)}
                className="flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-[var(--text-muted)] hover:bg-[var(--surface-high)] hover:text-[var(--text-primary)]"
              >
                <ArrowLeft size={13} /> Recordings
              </button>
            ) : (
              <Film size={16} className="text-[var(--primary)]" />
            )}
            <h2 className="truncate text-sm font-semibold text-[var(--text-primary)]">
              {playing ? playing.info.title || playing.info.name : "Session Recordings"}
            </h2>
          </div>
          <button
            type="button"
            onClick={close}
            className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--border)] hover:text-[var(--text-primary)]"
          >
            <X size={16} />
          </button>
        </div>

        <div className="min-h-0 overflow-y-auto p-5">
          {error && <p className="mb-3 text-xs text-[var(--danger)]">{error}</p>}
          {playing ? (
            <RecordingPlayer text={playing.text} />
          ) : recordings === null ? (
            <div className="flex items-center justify-center gap-2 py-12 text-xs text-[var(--text-muted)]">
              <LoaderCircle size={14} className="animate-spin" /> Loading…
            </div>
          ) : recordings.length === 0 ? (
            <div className="py-12 text-center text-xs text-[var(--text-muted)]">
              <p className="text-sm text-[var(--text-secondary)]">No recordings yet</p>
              <p className="mt-1">
                Start one from a terminal's right-click menu, or record every session in Settings → SSH & Sessions.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--border)] rounded-lg border border-[var(--border)]">
              {recordings.map((info) => (
                <div key={info.name} className="flex items-center gap-3 px-3 py-2.5">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm text-[var(--text-primary)]">{info.title || info.name}</p>
                    <p className="text-[11px] text-[var(--text-muted)]">
                      {formatDate(info.startedAt)} · {formatDuration(info.durationSecs)} · {formatBytes(info.sizeBytes)} ·{" "}
                      {info.cols}×{info.rows}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => play(info)}
                    disabled={loading === info.name}
                    className="flex items-center gap-1.5 rounded-lg bg-[var(--primary)]/15 px-2.5 py-1 text-xs font-medium text-[var(--primary)] hover:bg-[var(--primary)]/25 disabled:opacity-50"
                  >
                    {loading === info.name ? <LoaderCircle size={12} className="animate-spin" /> : <Play size={12} />} Play
                  </button>
                  <button
                    type="button"
                    title="Export as .cast (plays in asciinema)"
                    onClick={() => exportRecording(info)}
                    className="rounded-md p-1.5 text-[var(--text-muted)] hover:bg-[var(--surface-high)] hover:text-[var(--text-primary)]"
                  >
                    <Download size={14} />
                  </button>
                  <button
                    type="button"
                    title="Delete"
                    onClick={() => remove(info)}
                    className="rounded-md p-1.5 text-[var(--text-muted)] hover:bg-[var(--danger)]/15 hover:text-[var(--danger)]"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              ))}
            </div>
          )}
          {!playing && (
            <p className="mt-3 text-[11px] text-[var(--text-muted)]">
              Recordings keep what the server showed (never what you typed) in{" "}
              <span className="font-mono">~/.local/share/termimus/recordings</span>, readable only by you. Passwords
              that a program echoes, or secrets printed on screen, are in them.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
