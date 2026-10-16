import { useEffect, useState } from "react";
import { Braces } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { useSnippetVarsStore } from "../../stores/useSnippetVarsStore";
import { fillSnippet } from "../../lib/snippetVars";

/** Asks for a snippet's `{{variables}}` before it runs. */
export function SnippetVariablesModal() {
  const { request, lastValues, finish } = useSnippetVarsStore(
    useShallow((s) => ({ request: s.request, lastValues: s.lastValues, finish: s.finish }))
  );
  const [values, setValues] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!request) return;
    setValues(Object.fromEntries(request.variables.map((v) => [v.name, lastValues[v.name] ?? v.defaultValue])));
    // Only when a new request opens; typing must not be reset.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request]);

  useEffect(() => {
    if (!request) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        // Not also un-maximizing the pane behind the dialog.
        e.stopImmediatePropagation();
        finish(null);
      }
    }
    window.addEventListener("keydown", handleKeyDown, true);
    return () => window.removeEventListener("keydown", handleKeyDown, true);
  }, [request, finish]);

  if (!request) return null;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          finish(values);
        }}
        className="w-full max-w-md rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] p-5 shadow-2xl"
      >
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--primary)]/15 text-[var(--primary)]">
            <Braces size={18} />
          </div>
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-[var(--text-primary)]">{request.title}</h2>
            <p className="text-xs text-[var(--text-muted)]">Fill in the values for this run.</p>
          </div>
        </div>
        <div className="space-y-3">
          {request.variables.map((variable, index) => (
            <div key={variable.name}>
              <label className="mb-1 block font-mono text-[11px] text-[var(--text-muted)]">{variable.name}</label>
              <input
                autoFocus={index === 0}
                type={request.secret ? "password" : "text"}
                autoComplete="off"
                value={values[variable.name] ?? ""}
                onChange={(e) => setValues((v) => ({ ...v, [variable.name]: e.target.value }))}
                placeholder={variable.defaultValue || variable.name}
                spellCheck={false}
                className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 font-mono text-xs text-[var(--text-primary)] focus:border-[var(--primary)] focus:outline-none"
              />
            </div>
          ))}
        </div>
        {request.secret ? (
          <p className="mt-4 text-[11px] text-[var(--text-muted)]">Preview hidden: this snippet is marked secret.</p>
        ) : (
          <pre className="mt-4 max-h-32 overflow-auto rounded-lg border border-[var(--border)] bg-[var(--canvas)] p-2.5 font-mono text-[11px] text-[var(--text-secondary)] whitespace-pre-wrap break-all">
            {fillSnippet(request.command, values)}
          </pre>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => finish(null)}
            className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--surface-highest)]"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)]"
          >
            Run
          </button>
        </div>
      </form>
    </div>
  );
}
