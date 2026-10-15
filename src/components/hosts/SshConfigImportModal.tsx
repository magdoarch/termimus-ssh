import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  CircleCheck,
  FileInput,
  KeyRound,
  LoaderCircle,
  Lock,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
  Waypoints,
  X,
  type LucideIcon,
} from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import {
  api,
  type SshConfigHostPreview,
  type SshConfigImportResult,
  type SshConfigKeyPreview,
  type SshConfigPreview,
} from "../../lib/api";
import { useHostStore } from "../../stores/useHostStore";
import { useKeychainStore } from "../../stores/useKeychainStore";
import { useKnownHostsStore } from "../../stores/useKnownHostsStore";
import { useVaultStore } from "../../stores/useVaultStore";

const DEFAULT_GROUP = "SSH Config";

const fileName = (path: string) => path.split("/").pop() || path;

type Tone = "muted" | "success" | "warning" | "danger";

const TONE_TEXT: Record<Tone, string> = {
  muted: "text-[var(--text-muted)]",
  success: "text-[var(--success)]",
  warning: "text-[var(--warning)]",
  danger: "text-[var(--danger)]",
};

function Chip({ icon: Icon, tone = "muted", title, children }: { icon?: LucideIcon; tone?: Tone; title?: string; children: ReactNode }) {
  return (
    <span
      title={title}
      className={`inline-flex max-w-full items-center gap-1 rounded-md border border-[var(--border)] bg-[var(--surface-container)] px-1.5 py-0.5 ${TONE_TEXT[tone]}`}
    >
      {Icon && <Icon size={11} className="shrink-0" />}
      <span className="truncate">{children}</span>
    </span>
  );
}

/** How a host will log in, as a chip. */
function KeyChip({ host, keyInfo }: { host: SshConfigHostPreview; keyInfo?: SshConfigKeyPreview }) {
  if (!host.identityFile || !keyInfo) {
    return <Chip icon={Lock} title="No key: the password is asked when connecting">password at login</Chip>;
  }
  const name = fileName(keyInfo.path) + (host.defaultIdentity ? " (default)" : "");
  switch (keyInfo.status) {
    case "ok":
      return <Chip icon={KeyRound} title={keyInfo.displayPath}>{name}</Chip>;
    case "encrypted":
      return <Chip icon={KeyRound} tone="warning" title={`${keyInfo.displayPath} is encrypted`}>{name}, encrypted</Chip>;
    default:
      return (
        <Chip icon={TriangleAlert} tone="danger" title={`${keyInfo.detail ?? ""} — the password is asked when connecting`}>
          {name}, {keyInfo.status === "missing" ? "not found" : "unusable"}
        </Chip>
      );
  }
}

function keyStatus(key: SshConfigKeyPreview): { text: string; tone: Tone } {
  if (key.keychainName) return { text: `In Keychain as ${key.keychainName}`, tone: "success" };
  switch (key.status) {
    case "ok":
      return { text: "Added to Keychain", tone: "muted" };
    case "encrypted":
      return { text: "Encrypted", tone: "warning" };
    case "missing":
      return { text: "Not found", tone: "danger" };
    default:
      return { text: "Can't be used", tone: "danger" };
  }
}

/**
 * Imports hosts from an OpenSSH client config (~/.ssh/config by default):
 * hosts, the keys they use (into the Keychain), ProxyJump bastions and the
 * host keys ~/.ssh/known_hosts already trusts.
 */
export function SshConfigImportModal({ onClose }: { onClose: () => void }) {
  const { isUnlocked, openUnlockPrompt } = useVaultStore(
    useShallow((s) => ({ isUnlocked: s.isUnlocked, openUnlockPrompt: s.openUnlockPrompt }))
  );
  const [pathInput, setPathInput] = useState("");
  // The path the preview was read from; the import uses the same one.
  const [loadedPath, setLoadedPath] = useState("");
  const [preview, setPreview] = useState<SshConfigPreview | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [passphrases, setPassphrases] = useState<Record<string, string>>({});
  const [useGroup, setUseGroup] = useState(true);
  const [groupName, setGroupName] = useState(DEFAULT_GROUP);
  const [trustKnownHosts, setTrustKnownHosts] = useState(true);
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [result, setResult] = useState<SshConfigImportResult | null>(null);

  const load = useCallback(async (path: string) => {
    setLoading(true);
    setLoadError(null);
    setImportError(null);
    try {
      const next = await api.previewSshConfig(path);
      setPreview(next);
      setLoadedPath(path);
      // Aliases of a host listed earlier start unticked.
      setSelected(new Set(next.hosts.filter((h) => !h.existingHost && !h.sameAs).map((h) => h.alias)));
      setPassphrases({});
    } catch (e) {
      setPreview(null);
      setLoadError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load("");
  }, [load]);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !importing) onClose();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [importing, onClose]);

  const hosts = useMemo(() => preview?.hosts ?? [], [preview]);
  const importable = useMemo(() => hosts.filter((h) => !h.existingHost), [hosts]);
  const chosen = useMemo(() => hosts.filter((h) => selected.has(h.alias)), [hosts, selected]);
  const keysByPath = useMemo(() => new Map((preview?.keys ?? []).map((k) => [k.path, k])), [preview]);
  // Keys the chosen hosts, and the jump hosts created for them, log in with.
  const usedKeys = useMemo(() => {
    const paths = new Set<string>();
    for (const h of chosen) {
      if (h.identityFile) paths.add(h.identityFile);
      for (const path of h.jumpIdentityFiles) paths.add(path);
    }
    return [...paths].map((p) => keysByPath.get(p)).filter((k): k is SshConfigKeyPreview => !!k);
  }, [chosen, keysByPath]);
  const withKnownKey = chosen.filter((h) => h.knownHostKey).length;
  const allSelected = importable.length > 0 && importable.every((h) => selected.has(h.alias));

  function toggle(alias: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(alias)) next.delete(alias);
      else next.add(alias);
      return next;
    });
  }

  async function handleImport() {
    setImporting(true);
    setImportError(null);
    try {
      const keyPassphrases: Record<string, string> = {};
      for (const key of usedKeys) {
        const passphrase = passphrases[key.path];
        if (key.status === "encrypted" && passphrase) keyPassphrases[key.path] = passphrase;
      }
      const res = await api.importSshConfig({
        configPath: loadedPath || null,
        aliases: chosen.map((h) => h.alias),
        folderName: useGroup && groupName.trim() ? groupName.trim() : null,
        trustKnownHosts,
        keyPassphrases,
      });
      setPassphrases({});
      setResult(res);
      await Promise.all([
        useHostStore.getState().refresh(),
        useKeychainStore.getState().refresh(),
        useKnownHostsStore.getState().refresh(),
      ]);
    } catch (e) {
      setImportError(String(e));
    } finally {
      setImporting(false);
    }
  }

  const canImport = isUnlocked && chosen.length > 0 && !importing && !loading;

  return (
    <div
      onPointerDown={(e) => {
        if (e.target === e.currentTarget && !importing) onClose();
      }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
    >
      <div className="flex max-h-[85vh] w-full max-w-2xl flex-col rounded-xl border border-[var(--border)] bg-[var(--surface-low)] shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 border-b border-[var(--border)] px-5 py-3.5">
          <div className="flex min-w-0 items-center gap-2">
            <FileInput size={17} className="shrink-0 text-[var(--primary)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Import from SSH config</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={importing}
            className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--border)] hover:text-[var(--text-primary)] disabled:opacity-50"
          >
            <X size={16} />
          </button>
        </div>

        {result ? (
          <div className="space-y-4 overflow-y-auto px-5 py-5">
            <div className="flex items-start gap-3">
              <CircleCheck size={20} className="mt-0.5 shrink-0 text-[var(--success)]" />
              <div className="space-y-1 text-xs text-[var(--text-secondary)]">
                <p className="text-sm font-medium text-[var(--text-primary)]">
                  {result.hostsAdded === 0
                    ? "Nothing new to import"
                    : `Imported ${result.hostsAdded} host${result.hostsAdded === 1 ? "" : "s"}`}
                </p>
                {result.jumpHostsAdded > 0 && (
                  <p>
                    {result.jumpHostsAdded} jump host{result.jumpHostsAdded === 1 ? "" : "s"} added for ProxyJump
                  </p>
                )}
                {(result.keysAdded > 0 || result.keysReused > 0) && (
                  <p>
                    {result.keysAdded} key{result.keysAdded === 1 ? "" : "s"} added to the Keychain
                    {result.keysReused > 0 && `, ${result.keysReused} already there`}
                  </p>
                )}
                {result.hostKeysTrusted > 0 && (
                  <p>
                    {result.hostKeysTrusted} host key{result.hostKeysTrusted === 1 ? "" : "s"} trusted from known_hosts
                  </p>
                )}
              </div>
            </div>
            {result.warnings.length > 0 && (
              <ul className="space-y-1 rounded-lg border border-[var(--warning)]/30 bg-[var(--warning)]/10 p-2.5 text-[11px] text-[var(--warning)]">
                {result.warnings.map((w) => (
                  <li key={w} className="flex gap-1.5">
                    <TriangleAlert size={12} className="mt-px shrink-0" />
                    <span>{w}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <div className="min-h-0 space-y-5 overflow-y-auto px-5 py-4">
            {/* Config file */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                load(pathInput.trim());
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                value={pathInput}
                onChange={(e) => setPathInput(e.target.value)}
                placeholder="~/.ssh/config"
                spellCheck={false}
                className="min-w-0 flex-1 rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--primary)] focus:outline-none"
              />
              <button
                type="submit"
                disabled={loading}
                title="Read the config again"
                className="flex shrink-0 items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-high)] px-3 py-1.5 text-xs text-[var(--text-primary)] hover:bg-[var(--surface-highest)] disabled:opacity-50"
              >
                <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
                Load
              </button>
            </form>

            {loading && !preview && (
              <div className="flex items-center justify-center gap-2 py-10 text-xs text-[var(--text-muted)]">
                <LoaderCircle size={14} className="animate-spin" /> Reading the config…
              </div>
            )}

            {loadError && (
              <div className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 p-2.5 text-xs text-[var(--danger)]">
                {loadError}
              </div>
            )}

            {preview && (
              <>
                {preview.warnings.length > 0 && (
                  <ul className="space-y-1 rounded-lg border border-[var(--warning)]/30 bg-[var(--warning)]/10 p-2.5 text-[11px] text-[var(--warning)]">
                    {preview.warnings.map((w) => (
                      <li key={w} className="flex gap-1.5">
                        <TriangleAlert size={12} className="mt-px shrink-0" />
                        <span>{w}</span>
                      </li>
                    ))}
                  </ul>
                )}

                {/* Hosts */}
                <section>
                  <div className="mb-2 flex items-center justify-between">
                    <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                      Hosts in {preview.configPath}
                    </h3>
                    {importable.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setSelected(allSelected ? new Set() : new Set(importable.map((h) => h.alias)))}
                        className="text-[11px] text-[var(--primary)] hover:underline"
                      >
                        {allSelected ? "Select none" : "Select all"}
                      </button>
                    )}
                  </div>
                  {hosts.length === 0 ? (
                    <p className="rounded-lg border border-[var(--border)] px-3 py-6 text-center text-xs text-[var(--text-muted)]">
                      No hosts in this config. Wildcard entries like <span className="font-mono">Host *</span> only hold defaults.
                    </p>
                  ) : (
                    <div className="divide-y divide-[var(--border)] rounded-lg border border-[var(--border)]">
                      {hosts.map((h) => {
                        const disabled = !!h.existingHost;
                        return (
                          <label
                            key={h.alias}
                            className={`flex items-start gap-3 px-3 py-2.5 ${
                              disabled ? "opacity-60" : "cursor-pointer hover:bg-[var(--surface-container)]"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={selected.has(h.alias)}
                              disabled={disabled}
                              onChange={() => toggle(h.alias)}
                              className="mt-0.5 accent-[var(--primary)]"
                            />
                            <div className="min-w-0 flex-1">
                              <div className="flex min-w-0 items-baseline gap-2">
                                <span className="truncate text-sm font-medium text-[var(--text-primary)]">{h.alias}</span>
                                <span className="truncate font-mono text-[11px] text-[var(--text-muted)]">
                                  {h.username}@{h.address}
                                  {h.port !== 22 && `:${h.port}`}
                                </span>
                              </div>
                              <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[10px]">
                                {disabled ? (
                                  <Chip icon={CircleCheck} tone="success">
                                    Already added{h.existingHost !== h.alias && ` as ${h.existingHost}`}
                                  </Chip>
                                ) : (
                                  <KeyChip host={h} keyInfo={h.identityFile ? keysByPath.get(h.identityFile) : undefined} />
                                )}
                                {h.jumpChain.length > 0 && (
                                  <Chip icon={Waypoints} title={`ProxyJump ${h.proxyJump ?? ""}`}>
                                    via {h.jumpChain.join(" → ")}
                                  </Chip>
                                )}
                                {h.knownHostKey && (
                                  <Chip icon={ShieldCheck} title="~/.ssh/known_hosts has a key for this host">
                                    known host key
                                  </Chip>
                                )}
                                {h.sameAs && <Chip>same host as {h.sameAs}</Chip>}
                              </div>
                              {h.notes.map((note) => (
                                <p key={note} className="mt-1 flex gap-1 text-[11px] text-[var(--warning)]">
                                  <TriangleAlert size={12} className="mt-px shrink-0" />
                                  <span>{note}</span>
                                </p>
                              ))}
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  )}
                </section>

                {/* Keys */}
                {usedKeys.length > 0 && (
                  <section>
                    <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Keys</h3>
                    <div className="space-y-2">
                      {usedKeys.map((key) => {
                        const status = keyStatus(key);
                        return (
                          <div key={key.path} className="rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2">
                            <div className="flex min-w-0 items-center gap-2">
                              <KeyRound size={13} className="shrink-0 text-[var(--primary)]" />
                              <span className="truncate font-mono text-xs text-[var(--text-primary)]">{key.displayPath}</span>
                              {key.keyType && (
                                <span className="shrink-0 rounded border border-[var(--border)] px-1 py-px font-mono text-[9px] text-[var(--text-muted)]">
                                  {key.keyType}
                                </span>
                              )}
                              <span className={`ml-auto shrink-0 text-[11px] ${TONE_TEXT[status.tone]}`}>{status.text}</span>
                            </div>
                            {key.fingerprint && (
                              <p className="mt-1 truncate font-mono text-[10px] text-[var(--text-muted)]">{key.fingerprint}</p>
                            )}
                            {key.detail && <p className="mt-1 text-[11px] text-[var(--danger)]">{key.detail}</p>}
                            {key.status === "encrypted" && !key.keychainName && (
                              <input
                                type="password"
                                value={passphrases[key.path] ?? ""}
                                onChange={(e) => setPassphrases((p) => ({ ...p, [key.path]: e.target.value }))}
                                placeholder="Passphrase to save (optional, otherwise asked when connecting)"
                                autoComplete="off"
                                className="mt-2 w-full rounded-md border border-[var(--border)] bg-[var(--canvas)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--primary)] focus:outline-none"
                              />
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </section>
                )}

                {/* Options */}
                {hosts.length > 0 && (
                  <section className="space-y-3 text-xs text-[var(--text-secondary)]">
                    <div className="flex items-center gap-2.5">
                      <input
                        id="ssh-import-group"
                        type="checkbox"
                        checked={useGroup}
                        onChange={(e) => setUseGroup(e.target.checked)}
                        className="accent-[var(--primary)]"
                      />
                      <label htmlFor="ssh-import-group" className="cursor-pointer">
                        Put them in the group
                      </label>
                      <input
                        type="text"
                        value={groupName}
                        disabled={!useGroup}
                        onChange={(e) => setGroupName(e.target.value)}
                        className="w-44 rounded-md border border-[var(--border)] bg-[var(--surface-container)] px-2.5 py-1 text-xs text-[var(--text-primary)] focus:border-[var(--primary)] focus:outline-none disabled:opacity-50"
                      />
                    </div>
                    {preview.knownHostsFiles.length > 0 && (
                      <label className="flex cursor-pointer items-start gap-2.5">
                        <input
                          type="checkbox"
                          checked={trustKnownHosts}
                          onChange={(e) => setTrustKnownHosts(e.target.checked)}
                          className="mt-0.5 accent-[var(--primary)]"
                        />
                        <span>
                          Trust the host keys in {preview.knownHostsFiles.join(", ")}
                          <span className="text-[var(--text-muted)]">
                            {" "}
                            ({withKnownKey} of {chosen.length} selected)
                          </span>
                          <span className="mt-0.5 block text-[11px] text-[var(--text-muted)]">
                            The first connection is checked against these keys instead of trusting whatever the server
                            presents. A key Termimus already trusts is never replaced.
                          </span>
                        </span>
                      </label>
                    )}
                  </section>
                )}

                {importError && (
                  <div className="rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 p-2.5 text-xs text-[var(--danger)]">
                    {importError}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 border-t border-[var(--border)] px-5 py-3">
          {result ? (
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)]"
            >
              Done
            </button>
          ) : (
            <>
              {!isUnlocked && (
                <span className="mr-auto flex items-center gap-2 text-[11px] text-[var(--warning)]">
                  <Lock size={12} /> Unlock the vault to import keys and hosts.
                  <button type="button" onClick={openUnlockPrompt} className="text-[var(--primary)] hover:underline">
                    Unlock
                  </button>
                </span>
              )}
              <button
                type="button"
                onClick={onClose}
                disabled={importing}
                className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--surface-highest)] disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleImport}
                disabled={!canImport}
                className="flex items-center gap-1.5 rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)] disabled:opacity-50"
              >
                {importing && <LoaderCircle size={13} className="animate-spin" />}
                {importing
                  ? "Importing…"
                  : chosen.length === 0
                  ? "Import"
                  : `Import ${chosen.length} host${chosen.length === 1 ? "" : "s"}`}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
