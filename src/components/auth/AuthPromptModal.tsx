import { useEffect, useRef, useState } from "react";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { useAuthPromptStore } from "../../stores/useAuthPromptStore";
import type { AuthPromptEvent } from "../../lib/api";

/** OTP-style prompts get a numeric keypad and one-time-code autofill. */
const isCodePrompt = (prompt: string) => /code|token|otp|passcode|verification|2fa/i.test(prompt);

const fieldLabel = (prompt: string) => prompt.replace(/[:\s]+$/, "").trim() || "Response";

/**
 * Keyboard-interactive login prompts (2FA codes, Duo, PAM questions) from
 * any SSH login: terminal, SFTP, tunnels, jump hosts. One prompt at a time;
 * further ones wait in the queue.
 */
export function AuthPromptModal() {
  const { queue, respond } = useAuthPromptStore(useShallow((s) => ({ queue: s.queue, respond: s.respond })));
  const current = queue[0];
  if (!current) return null;
  // Keyed by request so typed answers never carry over to the next prompt.
  return <PromptDialog key={current.requestId} request={current} pending={queue.length - 1} respond={respond} />;
}

function PromptDialog({
  request,
  pending,
  respond,
}: {
  request: AuthPromptEvent;
  pending: number;
  respond: (requestId: string, answers: string[] | null) => Promise<void>;
}) {
  const [answers, setAnswers] = useState<string[]>(() => request.prompts.map(() => ""));
  const [revealed, setRevealed] = useState<boolean[]>(() => request.prompts.map(() => false));
  const firstField = useRef<HTMLInputElement>(null);

  useEffect(() => {
    firstField.current?.focus();
  }, []);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") respond(request.requestId, null);
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [request.requestId, respond]);

  const title = request.name.trim() || "Additional verification required";

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm select-none">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          respond(request.requestId, answers);
        }}
        className="w-full max-w-sm rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] p-6 shadow-2xl"
      >
        <div className="mb-4 flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--primary)]/15 text-[var(--primary)]">
            <ShieldCheck size={20} />
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h2>
            <p className="truncate font-mono text-[11px] text-[var(--text-muted)]" title={request.target}>
              {request.target}
            </p>
          </div>
          {pending > 0 && (
            <span className="ml-auto shrink-0 rounded-md border border-[var(--border)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]">
              +{pending} waiting
            </span>
          )}
        </div>

        {request.instructions.trim() && (
          <p className="mb-4 whitespace-pre-wrap rounded-lg border border-[var(--border)] bg-[var(--surface-container)] p-2.5 text-xs text-[var(--text-secondary)]">
            {request.instructions.trim()}
          </p>
        )}

        <div className="space-y-3">
          {request.prompts.map((p, i) => {
            const code = isCodePrompt(p.prompt);
            const hidden = !p.echo && !revealed[i];
            return (
              <div key={i}>
                <label className="mb-1.5 block text-xs font-medium text-[var(--text-muted)]">{fieldLabel(p.prompt)}</label>
                <div className="relative">
                  <input
                    ref={i === 0 ? firstField : undefined}
                    type={hidden ? "password" : "text"}
                    value={answers[i]}
                    onChange={(e) => setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))}
                    autoComplete={code ? "one-time-code" : "off"}
                    inputMode={code ? "numeric" : undefined}
                    spellCheck={false}
                    className={`w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] focus:outline-none ${
                      code ? "font-mono tracking-[0.2em]" : ""
                    } ${p.echo ? "" : "pr-9"}`}
                  />
                  {!p.echo && (
                    <button
                      type="button"
                      onClick={() => setRevealed((r) => r.map((v, j) => (j === i ? !v : v)))}
                      title={hidden ? "Show" : "Hide"}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                    >
                      {hidden ? <Eye size={14} /> : <EyeOff size={14} />}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => respond(request.requestId, null)}
            className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] transition-colors hover:bg-[var(--surface-highest)]"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] shadow-sm transition-colors hover:bg-[var(--primary-hover)]"
          >
            Continue
          </button>
        </div>
      </form>
    </div>
  );
}
