import { useEffect, useState } from "react";
import { Check, Copy, ShieldCheck, Trash2, Undo2 } from "lucide-react";
import { api, type TotpCode } from "../../lib/api";
import { copyText } from "../../lib/clipboard";

/** What saving the host does with its 2FA secret. */
export type TotpChange = { kind: "keep" } | { kind: "set"; secret: string } | { kind: "remove" };

/** The value for HostInput.totp_secret. */
export const totpSecretInput = (change: TotpChange): string | undefined =>
  change.kind === "set" ? change.secret : change.kind === "remove" ? "" : undefined;

function CodeDisplay({ code }: { code: TotpCode }) {
  const [copied, setCopied] = useState(false);
  const grouped = code.code.length === 6 ? `${code.code.slice(0, 3)} ${code.code.slice(3)}` : code.code;
  return (
    <div className="flex items-center gap-3">
      <span className="font-mono text-lg tracking-[0.15em] text-[var(--text-primary)]">{grouped}</span>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-[var(--surface-high)]" title={`${code.remaining}s left`}>
        <div
          className="h-full rounded-full bg-[var(--primary)] transition-[width] duration-1000 ease-linear"
          style={{ width: `${(code.remaining / code.period) * 100}%` }}
        />
      </div>
      <button
        type="button"
        onClick={async () => {
          await copyText(code.code);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
        title="Copy code"
        className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
      >
        {copied ? <Check size={13} /> : <Copy size={13} />}
      </button>
    </div>
  );
}

/**
 * 2FA (TOTP) secret of an SSH host. With one saved, the one-time code a
 * server asks for at login is filled in, so the 2FA dialog doesn't appear.
 */
export function TotpField({
  hostId,
  configured,
  change,
  onChange,
}: {
  hostId?: string;
  configured: boolean;
  change: TotpChange;
  onChange: (change: TotpChange) => void;
}) {
  const [code, setCode] = useState<TotpCode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const secret = change.kind === "set" ? change.secret : "";
  const showSaved = configured && change.kind === "keep" && hostId;

  // Refresh the shown code every second (the secret stays in the backend).
  useEffect(() => {
    if (!(change.kind === "set" && secret.trim()) && !showSaved) {
      setCode(null);
      setError(null);
      return;
    }
    let cancelled = false;
    const refresh = async () => {
      try {
        const next = change.kind === "set" ? await api.totpPreview(secret) : await api.hostTotpCode(hostId!);
        if (!cancelled) {
          setCode(next);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setCode(null);
          setError(String(e));
        }
      }
    };
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [change.kind, secret, showSaved, hostId]);

  return (
    <div className="space-y-2 rounded-xl border border-[var(--border)] bg-[var(--surface-container)]/40 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 font-medium text-[var(--text-muted)]">
          <ShieldCheck size={13} className="text-[var(--primary)]" />
          Two-factor code (TOTP)
        </span>
        {change.kind === "keep" && !configured && (
          <button
            type="button"
            onClick={() => onChange({ kind: "set", secret: "" })}
            className="text-[11px] font-medium text-[var(--primary)] hover:underline"
          >
            Add secret
          </button>
        )}
        {change.kind === "keep" && configured && (
          <div className="flex items-center gap-3 text-[11px]">
            <button type="button" onClick={() => onChange({ kind: "set", secret: "" })} className="text-[var(--primary)] hover:underline">
              Replace
            </button>
            <button
              type="button"
              onClick={() => onChange({ kind: "remove" })}
              className="flex items-center gap-1 text-[var(--danger)] hover:underline"
            >
              <Trash2 size={11} /> Remove
            </button>
          </div>
        )}
        {change.kind !== "keep" && (
          <button
            type="button"
            onClick={() => onChange({ kind: "keep" })}
            className="flex items-center gap-1 text-[11px] text-[var(--text-muted)] hover:text-[var(--text-primary)]"
          >
            <Undo2 size={11} /> {configured ? "Keep the saved one" : "Cancel"}
          </button>
        )}
      </div>

      {change.kind === "set" && (
        <input
          type="password"
          autoFocus
          value={change.secret}
          onChange={(e) => onChange({ kind: "set", secret: e.target.value })}
          placeholder="Secret key (base32) or otpauth://totp/… URI"
          autoComplete="off"
          spellCheck={false}
          className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/60 focus:border-[var(--primary)] focus:outline-none"
        />
      )}
      {change.kind === "remove" && (
        <p className="text-[11px] text-[var(--warning)]">The saved secret is removed when you save the host.</p>
      )}
      {code && <CodeDisplay code={code} />}
      {error && change.kind === "set" && <p className="text-[11px] text-[var(--danger)]">{error}</p>}
      <p className="text-[11px] leading-relaxed text-[var(--text-muted)]">
        {change.kind === "set" || !configured
          ? "The same secret your authenticator app uses (shown when you set up 2FA, or in its QR code). Codes the server asks for at login are filled in automatically; the secret is encrypted in your vault."
          : "Codes the server asks for at login are filled in automatically."}
      </p>
    </div>
  );
}
