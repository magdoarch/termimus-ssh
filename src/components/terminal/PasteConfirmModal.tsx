import { useEffect } from "react";
import { ClipboardPaste } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { usePasteConfirmStore } from "../../stores/usePasteConfirmStore";
import { useSettingsStore } from "../../stores/useSettingsStore";

const PREVIEW_LINES = 12;

/**
 * Asks before multi-line text goes into a shell that would run each line as
 * it arrives (no bracketed paste). Settings > SSH & Sessions turns it off.
 */
export function PasteConfirmModal() {
  const { request, close } = usePasteConfirmStore(useShallow((s) => ({ request: s.request, close: s.close })));

  useEffect(() => {
    if (!request) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        close();
        request?.done();
      }
    }
    window.addEventListener("keydown", handleKeyDown, true);
    return () => window.removeEventListener("keydown", handleKeyDown, true);
  }, [request, close]);

  if (!request) return null;

  const lines = request.text.split("\n");
  const endsWithNewline = request.text.endsWith("\n");
  const lineCount = endsWithNewline ? lines.length - 1 : lines.length;
  const shown = lines.slice(0, PREVIEW_LINES).join("\n");
  const finish = (text: string | null) => {
    close();
    if (text !== null) request.paste(text);
    request.done();
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] p-5 shadow-2xl">
        <div className="mb-3 flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--warning)]/15 text-[var(--warning)]">
            <ClipboardPaste size={18} />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Paste {lineCount} line{lineCount === 1 ? "" : "s"}?
            </h2>
            <p className="text-xs text-[var(--text-muted)]">
              The shell runs every line that ends with a newline as soon as it is pasted.
            </p>
          </div>
        </div>
        <pre className="max-h-56 overflow-auto rounded-lg border border-[var(--border)] bg-[var(--canvas)] p-2.5 font-mono text-[11px] text-[var(--text-primary)] whitespace-pre-wrap break-all select-text">
          {shown}
          {lines.length > PREVIEW_LINES && `\n… ${lines.length - PREVIEW_LINES} more`}
        </pre>
        <label className="mt-3 flex items-center gap-2 text-[11px] text-[var(--text-muted)]">
          <input
            type="checkbox"
            onChange={(e) => useSettingsStore.getState().setConfirmMultilinePaste(!e.target.checked)}
            className="accent-[var(--primary)]"
          />
          Don't ask again (Settings → SSH & Sessions)
        </label>
        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={() => finish(null)}
            className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--surface-highest)]"
          >
            Cancel
          </button>
          {endsWithNewline && (
            <button
              type="button"
              onClick={() => finish(request.text.replace(/\n+$/, ""))}
              className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--surface-highest)]"
              title="The last line waits for Enter"
            >
              Paste without the last Enter
            </button>
          )}
          <button
            type="button"
            autoFocus
            onClick={() => finish(request.text)}
            className="rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)]"
          >
            Paste
          </button>
        </div>
      </div>
    </div>
  );
}
