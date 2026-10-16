import { useEffect, useState } from "react";
import { CircleCheck, KeyRound, LoaderCircle, X } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { dialogOnTop } from "../../lib/dialogs";
import { api, isSshHost, type HostInput } from "../../lib/api";
import { useHostStore } from "../../stores/useHostStore";
import { useKeychainStore } from "../../stores/useKeychainStore";
import { useInstallKeyStore } from "../../stores/useInstallKeyStore";
import { CustomSelect } from "../ui/CustomSelect";

type Status =
  | { kind: "idle" }
  | { kind: "installing" }
  | { kind: "done"; alreadyInstalled: boolean }
  | { kind: "switched" }
  | { kind: "error"; message: string };

/**
 * Adds a Keychain key's public half to a host's ~/.ssh/authorized_keys, like
 * ssh-copy-id, logging in the way the host is set up now (e.g. its password).
 * Afterwards the host can be switched to log in with the key.
 */
export function InstallKeyModal() {
  const { target, close } = useInstallKeyStore(useShallow((s) => ({ target: s.target, close: s.close })));
  const hosts = useHostStore((s) => s.hosts);
  const keys = useKeychainStore((s) => s.items).filter((item) => item.public_key && item.kind !== "password");
  const [hostId, setHostId] = useState("");
  const [credentialId, setCredentialId] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  useEffect(() => {
    if (!target) return;
    setHostId(target.hostId ?? "");
    setCredentialId(target.credentialId ?? "");
    setStatus({ kind: "idle" });
  }, [target]);

  useEffect(() => {
    if (!target) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !dialogOnTop() && status.kind !== "installing") close();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [target, status.kind, close]);

  if (!target) return null;

  const host = hosts.find((h) => h.id === hostId);
  const key = keys.find((k) => k.id === credentialId);
  const usesKey = host?.auth_method === "private_key" && host.credential_id === credentialId;

  async function install() {
    if (!host || !key) return;
    setStatus({ kind: "installing" });
    try {
      const result = await api.installPublicKey(host.id, key.id);
      setStatus({ kind: "done", alreadyInstalled: result.alreadyInstalled });
    } catch (e) {
      setStatus({ kind: "error", message: String(e) });
    }
  }

  async function switchToKey() {
    if (!host || !key) return;
    const input: HostInput = {
      folder_id: host.folder_id ?? null,
      label: host.label,
      address: host.address,
      port: host.port,
      username: host.username,
      auth_method: "private_key",
      credential_id: key.id,
      tags: host.tags,
      os_icon: host.os_icon ?? null,
      jump_host_id: host.jump_host_id ?? null,
      protocol: host.protocol,
      protocol_options: host.protocol_options ?? null,
    };
    try {
      await useHostStore.getState().saveHost(input, host.id);
      setStatus({ kind: "switched" });
    } catch (e) {
      setStatus({ kind: "error", message: String(e) });
    }
  }

  const busy = status.kind === "installing";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between border-b border-[var(--border)] pb-3">
          <div className="flex items-center gap-2">
            <KeyRound size={17} className="text-[var(--primary)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Install SSH key on a host</h2>
          </div>
          <button
            type="button"
            onClick={close}
            disabled={busy}
            className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--border)] hover:text-[var(--text-primary)] disabled:opacity-50"
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-3 text-xs">
          <div>
            <label className="mb-1.5 block font-medium text-[var(--text-muted)]">Key</label>
            <CustomSelect
              value={credentialId}
              onChange={(v) => {
                setCredentialId(v);
                setStatus({ kind: "idle" });
              }}
              disabled={busy}
              placeholder="Choose a Keychain key..."
              options={keys.map((k) => ({ value: k.id, label: k.name, description: k.key_type }))}
            />
          </div>
          <div>
            <label className="mb-1.5 block font-medium text-[var(--text-muted)]">Host</label>
            <CustomSelect
              value={hostId}
              onChange={(v) => {
                setHostId(v);
                setStatus({ kind: "idle" });
              }}
              disabled={busy}
              placeholder="Choose an SSH host..."
              options={hosts
                .filter(isSshHost)
                .map((h) => ({ value: h.id, label: h.label, description: `${h.username}@${h.address}` }))}
            />
          </div>
          {key && (
            <p className="truncate rounded-lg border border-[var(--border)] bg-[var(--canvas)] p-2 font-mono text-[10px] text-[var(--text-muted)]" title={key.public_key}>
              {key.public_key}
            </p>
          )}
          <p className="text-[11px] leading-relaxed text-[var(--text-muted)]">
            Adds the public key to <span className="font-mono">~/.ssh/authorized_keys</span> on the host (like{" "}
            <span className="font-mono">ssh-copy-id</span>), logging in the way the host is set up now. A key that is
            already there isn't added twice.
          </p>

          {status.kind === "error" && (
            <div className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 p-2.5 text-[var(--danger)]">
              {status.message}
            </div>
          )}
          {(status.kind === "done" || status.kind === "switched") && host && key && (
            <div className="flex items-start gap-2 rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/10 p-2.5 text-[var(--success)]">
              <CircleCheck size={14} className="mt-0.5 shrink-0" />
              <span>
                {status.kind === "switched"
                  ? `${host.label} now logs in with ${key.name}.`
                  : status.alreadyInstalled
                  ? `${key.name} was already authorized on ${host.label}.`
                  : `${key.name} is now authorized on ${host.label}.`}
              </span>
            </div>
          )}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          {status.kind === "done" && !usesKey && key?.kind === "private_key" ? (
            <>
              <button
                type="button"
                onClick={close}
                className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--surface-highest)]"
              >
                Done
              </button>
              <button
                type="button"
                onClick={switchToKey}
                className="rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)]"
              >
                Log in to {host?.label} with this key
              </button>
            </>
          ) : status.kind === "done" || status.kind === "switched" ? (
            <button
              type="button"
              onClick={close}
              className="rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)]"
            >
              Done
            </button>
          ) : (
            <>
              <button
                type="button"
                onClick={close}
                disabled={busy}
                className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--surface-highest)] disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={install}
                disabled={!host || !key || busy}
                className="flex items-center gap-1.5 rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)] disabled:opacity-50"
              >
                {busy && <LoaderCircle size={13} className="animate-spin" />}
                {busy ? "Installing…" : "Install key"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
