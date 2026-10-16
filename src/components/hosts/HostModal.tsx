import { useState, useEffect } from "react";
import {
  X,
  Key,
  Lock,
  Copy,
  Check,
  KeyRound,
  UserCheck,
  Eye,
  EyeOff,
  Cpu,
  Monitor,
  MonitorSmartphone,
  Terminal as TerminalIcon,
  ShieldAlert,
  Unlock,
} from "lucide-react";
import { useHostStore } from "../../stores/useHostStore";
import { useKeychainStore } from "../../stores/useKeychainStore";
import { api, DEFAULT_PORTS, Host, HostInput, HostProtocol, isSshHost, RdpOptions, VncOptions } from "../../lib/api";
import { DistroBadge, DISTRO_OPTIONS } from "./DistroBadge";
import { CustomSelect } from "../ui/CustomSelect";
import { copyText } from "../../lib/clipboard";

interface HostModalProps {
  onOpenKeychain?: () => void;
}

export function HostModal({ onOpenKeychain }: HostModalProps = {}) {
  const { isHostModalOpen, editingHost, templateHost, defaultFolderId, closeHostModal, saveHost, folders, hosts } =
    useHostStore();
  const { items: keychainItems } = useKeychainStore();

  const [label, setLabel] = useState("");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("root");
  const [protocol, setProtocol] = useState<HostProtocol>("ssh");
  const [authMethod, setAuthMethod] = useState<"password" | "private_key" | "none">("password");
  const [vncOptions, setVncOptions] = useState<VncOptions>({});
  const [rdpOptions, setRdpOptions] = useState<RdpOptions>({});
  const [secret, setSecret] = useState("");
  const [tagInput, setTagInput] = useState("");
  const [folderId, setFolderId] = useState<string>("");
  const [osIcon, setOsIcon] = useState<string>("");
  const [jumpHostId, setJumpHostId] = useState<string>("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Keychain selection
  const [selectedCredentialId, setSelectedCredentialId] = useState<string>("");
  const [copied, setCopied] = useState(false);

  // Password reveal (Termius-style): masked by default, fetched lazily and
  // shown in plain text only when the user clicks the eye icon.
  const [showPassword, setShowPassword] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);

  // Only actual private keys can authenticate an SSH session — a Keychain
  // item saved from a public key (ssh-rsa/ssh-ed25519 ...) has no private
  // key material and would fail to connect, so it's excluded here.
  const availableKeys = keychainItems.filter((i) => i.kind === "private_key");
  const availableIdentities = keychainItems.filter((i) => i.kind === "password");

  const selectedKeyItem = availableKeys.find(
    (k) => k.id === selectedCredentialId
  );
  const selectedIdentityItem = availableIdentities.find(
    (i) => i.id === selectedCredentialId
  );

  useEffect(() => {
    setShowPassword(false);
    if (editingHost) {
      // ── EDIT mode ──────────────────────────────────────────────────────────
      setLabel(editingHost.label);
      setAddress(editingHost.address);
      setPort(editingHost.port);
      setUsername(editingHost.username);
      const isPrivateKey = editingHost.auth_method === "private_key";
      setAuthMethod(isPrivateKey ? "private_key" : editingHost.auth_method === "none" ? "none" : "password");
      loadProtocolFields(editingHost);
      setTagInput(editingHost.tags.join(", "));
      setFolderId(editingHost.folder_id ?? "");
      setOsIcon(editingHost.os_icon ?? "");
      setJumpHostId(editingHost.jump_host_id ?? "");

      const isKeychain = keychainItems.some(
        (i) => i.id === editingHost.credential_id
      );
      setSelectedCredentialId(isKeychain ? (editingHost.credential_id ?? "") : "");

      setSecret("");

      // Eagerly load saved password for existing hosts
      if (editingHost.auth_method === "password") {
        setPasswordLoading(true);
        api
          .getHostPassword(editingHost.id)
          .then((pwd) => {
            setSecret(pwd);
          })
          .catch((err) => {
            console.warn("Could not load host password:", err);
          })
          .finally(() => {
            setPasswordLoading(false);
          });
      }
    } else if (templateHost) {
      // ── DUPLICATE mode: pre-fill all configuration from the template host ──
      setLabel(`[Copy] ${templateHost.label}`);
      setAddress(templateHost.address);
      setPort(templateHost.port);
      setUsername(templateHost.username);
      const isPrivateKey = templateHost.auth_method === "private_key";
      setAuthMethod(isPrivateKey ? "private_key" : templateHost.auth_method === "none" ? "none" : "password");
      loadProtocolFields(templateHost);
      setTagInput(templateHost.tags.join(", "));
      setFolderId(templateHost.folder_id ?? defaultFolderId ?? "");
      setOsIcon(templateHost.os_icon ?? "");
      setJumpHostId(templateHost.jump_host_id ?? "");

      // If source host used a reusable Keychain item, preserve that link.
      // If it used an anonymous inline credential, clear it so user supplies new secret.
      const isKeychain = keychainItems.some(
        (i) => i.id === templateHost.credential_id
      );
      setSelectedCredentialId(isKeychain ? (templateHost.credential_id ?? "") : "");
      setSecret("");
    } else {
      // ── CREATE NEW mode ───────────────────────────────────────────────────
      setLabel("");
      setAddress("");
      setPort(DEFAULT_PORTS.ssh);
      setUsername("root");
      setAuthMethod("password");
      setProtocol("ssh");
      setVncOptions({});
      setRdpOptions({});
      setSelectedCredentialId("");
      setSecret("");
      setTagInput("");
      setFolderId(defaultFolderId ?? "");
      setOsIcon("");
      setJumpHostId("");
    }
    setError(null);
  }, [editingHost, templateHost, defaultFolderId, isHostModalOpen]);

  function loadProtocolFields(host: Host) {
    setProtocol(host.protocol ?? "ssh");
    let options = {};
    try {
      options = host.protocol_options ? JSON.parse(host.protocol_options) : {};
    } catch {
      // ignore malformed options
    }
    setVncOptions(host.protocol === "vnc" ? options : {});
    setRdpOptions(host.protocol === "rdp" ? options : {});
  }

  function handleProtocolChange(next: HostProtocol) {
    if (next === protocol) return;
    // Follow the default port unless the user typed a custom one.
    if (port === DEFAULT_PORTS[protocol]) setPort(DEFAULT_PORTS[next]);
    // Key auth is SSH-only; "no password" is VNC-only.
    if (next !== "ssh" && authMethod === "private_key") {
      setAuthMethod("password");
      setSelectedCredentialId("");
    }
    if (next !== "vnc" && authMethod === "none") setAuthMethod("password");
    setProtocol(next);
  }

  // When a keychain item is selected, update default username if not set
  function handleSelectCredential(id: string) {
    setSelectedCredentialId(id);
    setShowPassword(false);
    if (!id || id === "custom") return;

    const item = keychainItems.find((k) => k.id === id);
    if (item?.username && (!username.trim() || username === "root")) {
      setUsername(item.username);
    }
  }

  // Termius-style reveal: the password field stays masked and empty until the
  // user clicks the eye icon, which lazily decrypts and fills in the real
  // value on first click (either the host's own saved password, or the
  // selected Keychain identity's password).
  async function handleTogglePassword() {
    if (showPassword) {
      setShowPassword(false);
      return;
    }

    if (!secret) {
      setPasswordLoading(true);
      setError(null);
      try {
        const value = selectedCredentialId
          ? await api.getCredentialSecret(selectedCredentialId)
          : editingHost
          ? await api.getHostPassword(editingHost.id)
          : "";
        setSecret(value);
      } catch (err) {
        setError(String(err));
        setPasswordLoading(false);
        return;
      }
      setPasswordLoading(false);
    }
    setShowPassword(true);
  }

  // Close modal on Escape key press (use capture phase so CustomSelect's bubble-phase
  // handler can call stopImmediatePropagation() first when its dropdown is open)
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && isHostModalOpen) {
        closeHostModal();
      }
    }
    window.addEventListener("keydown", handleKeyDown, { capture: false });
    return () => window.removeEventListener("keydown", handleKeyDown, { capture: false });
  }, [isHostModalOpen, closeHostModal]);

  if (!isHostModalOpen) return null;

  async function handleCopyPublicKey(keyText?: string | null) {
    if (!keyText) return;
    try {
      await copyText(keyText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      setError(`Failed to copy to clipboard: ${err}`);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!address.trim()) {
      setError("Address (IP or hostname) is required");
      return;
    }
    const isVnc = protocol === "vnc";
    if (!isVnc && !username.trim()) {
      setError("Username is required");
      return;
    }

    if (authMethod === "private_key" && !selectedCredentialId) {
      setError("Please select an SSH key from Keychain");
      return;
    }

    const tags = tagInput
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    const credentialIdToSave =
      authMethod === "private_key"
        ? selectedCredentialId
        : selectedCredentialId || null;

    setSubmitting(true);
    try {
      const input: HostInput = {
        label: label.trim() || address.trim(),
        address: address.trim(),
        port: Number(port) || DEFAULT_PORTS[protocol],
        username: isVnc ? "" : username.trim(),
        auth_method: authMethod,
        credential_id: authMethod === "none" ? null : credentialIdToSave,
        secret:
          authMethod === "password"
            ? selectedCredentialId
              ? undefined
              : secret
              ? secret
              : undefined
            : undefined,
        passphrase: undefined,
        tags,
        folder_id: folderId || null,
        os_icon: osIcon || null,
        jump_host_id: jumpHostId || null,
        protocol,
        protocol_options: isVnc
          ? JSON.stringify(vncOptions)
          : protocol === "rdp"
          ? JSON.stringify({ ...rdpOptions, domain: rdpOptions.domain?.trim() || undefined })
          : null,
      };

      await saveHost(input, editingHost?.id);
      closeHostModal();
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      onPointerDown={(e) => {
        // Use onPointerDown (fires before click) so the backdrop close does NOT
        // race with the same click that just opened the modal.  The target guard
        // ensures we only close when the user actually clicks the dark backdrop
        // area, not the inner panel.  e.preventDefault() is intentionally omitted
        // so that text-input focus inside the modal still works normally.
        if (e.target === e.currentTarget) closeHostModal();
      }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
    >
      <div className="w-full max-w-4xl rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="mb-5 flex items-center justify-between border-b border-[var(--border)] pb-3.5">
          <h2 className="text-base font-semibold text-[var(--text-primary)]">
            {editingHost ? "Edit Host" : "New Host"}
          </h2>
          <button
            type="button"
            onClick={closeHostModal}
            className="rounded-lg p-1.5 text-[var(--text-muted)] hover:bg-[var(--surface-high)] hover:text-[var(--text-primary)] transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 p-2.5 text-xs text-[var(--danger)]">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
            {/* LEFT COLUMN: GENERAL & CONNECTION */}
            <div className="space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                General & Connection
              </h3>

              <div>
                <label className="mb-1.5 block font-medium text-[var(--text-muted)]">Protocol</label>
                <div className="flex gap-2">
                  {([
                    { value: "ssh", label: "SSH", title: "SSH terminal", icon: TerminalIcon },
                    { value: "vnc", label: "VNC", title: "VNC remote desktop (Linux, macOS)", icon: Monitor },
                    { value: "rdp", label: "RDP", title: "RDP remote desktop (Windows, xrdp)", icon: MonitorSmartphone },
                  ] as const).map(({ value, label: optionLabel, title, icon: Icon }) => (
                    <button
                      key={value}
                      type="button"
                      title={title}
                      onClick={() => handleProtocolChange(value)}
                      className={`flex-1 flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-semibold transition ${
                        protocol === value
                          ? "bg-[var(--primary)] text-[var(--on-primary)] shadow-sm"
                          : "bg-[var(--surface-container)] text-[var(--text-secondary)] border border-[var(--border)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-high)]"
                      }`}
                    >
                      <Icon size={13} /> {optionLabel}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                  Label / Display Name
                </label>
                <input
                  type="text"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. Production Web 01"
                  className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:border-[var(--primary)] focus:outline-none transition-colors"
                />
              </div>

              <div>
                <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                  Group / Folder
                </label>
                <CustomSelect
                  value={folderId}
                  onChange={setFolderId}
                  options={[
                    { value: "", label: "No group (Ungrouped)" },
                    ...folders.map((f) => ({ value: f.id, label: f.name })),
                  ]}
                />
              </div>

              <div className="grid grid-cols-4 gap-3">
                <div className="col-span-3">
                  <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                    Address / Hostname *
                  </label>
                  <input
                    type="text"
                    required
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    placeholder="192.168.1.100 or server.example.com"
                    className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:border-[var(--primary)] focus:outline-none transition-colors"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                    Port
                  </label>
                  <input
                    type="number"
                    value={port}
                    onChange={(e) => setPort(Number(e.target.value))}
                    className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm font-mono text-[var(--text-primary)] focus:border-[var(--primary)] focus:outline-none transition-colors"
                  />
                </div>
              </div>

              {protocol !== "vnc" && (
              <div>
                <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                  Username *
                </label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={protocol === "rdp" ? "e.g. Administrator" : "e.g. root or ubuntu"}
                  className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm font-mono text-[var(--text-primary)] focus:border-[var(--primary)] focus:outline-none transition-colors"
                />
              </div>
              )}

              <div>
                <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                  Tags (comma separated)
                </label>
                <input
                  type="text"
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  placeholder="vps, homelab, docker, production"
                  className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:border-[var(--primary)] focus:outline-none transition-colors"
                />
              </div>

              {/* JUMP HOST / BASTION CONFIGURATION */}
              <div>
                <label className="mb-1.5 flex items-center justify-between font-medium text-[var(--text-muted)]">
                  <span>Connect via Jump Host / Bastion</span>
                  <span className="text-[10px] text-[var(--text-muted)] font-mono">SSH ProxyJump</span>
                </label>
                <CustomSelect
                  value={jumpHostId}
                  onChange={setJumpHostId}
                  options={[
                    { value: "", label: "Direct Connection (No Jump Host)" },
                    ...hosts
                      .filter((h) => h.id !== editingHost?.id && isSshHost(h))
                      .map((h) => ({
                        value: h.id,
                        label: h.label,
                        description: `(${h.username}@${h.address}:${h.port})`,
                      })),
                  ]}
                />
                <p className="mt-1 text-[11px] text-[var(--text-muted)] leading-relaxed">
                  Traffic to this host will be securely tunneled through the selected Bastion server.
                </p>
                {protocol === "vnc" && !jumpHostId && (
                  <div className="mt-2 flex items-start gap-2 rounded-md border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-2.5 py-2 text-[11px] text-[var(--warning)]">
                    <ShieldAlert size={13} className="shrink-0 mt-0.5" />
                    <span>
                      VNC traffic (including what you type) is not encrypted. Pick a Jump Host to
                      tunnel it over SSH, or only use this on a trusted network.
                    </span>
                  </div>
                )}
              </div>

              {protocol === "rdp" && (
                <div className="space-y-2">
                  <label className="block font-medium text-[var(--text-muted)]">RDP Options</label>
                  <input
                    type="text"
                    value={rdpOptions.domain ?? ""}
                    onChange={(e) => setRdpOptions({ ...rdpOptions, domain: e.target.value })}
                    placeholder="Domain (optional), e.g. CORP"
                    className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:border-[var(--primary)] focus:outline-none transition-colors"
                  />
                  <label className="flex items-center gap-2 text-[var(--text-secondary)]">
                    <input
                      type="checkbox"
                      checked={Boolean(rdpOptions.viewOnly)}
                      onChange={(e) => setRdpOptions({ ...rdpOptions, viewOnly: e.target.checked })}
                      className="accent-[var(--primary)]"
                    />
                    View only (don't send keyboard or mouse)
                  </label>
                  <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
                    The server's TLS key is trusted on first connect and checked on every
                    connect after that, like SSH host keys (see Settings → Trusted Host Keys).
                  </p>
                </div>
              )}

              {protocol === "vnc" && (
                <div className="space-y-2">
                  <label className="block font-medium text-[var(--text-muted)]">VNC Options</label>
                  <label className="flex items-center gap-2 text-[var(--text-secondary)]">
                    <input
                      type="checkbox"
                      checked={Boolean(vncOptions.viewOnly)}
                      onChange={(e) => setVncOptions({ ...vncOptions, viewOnly: e.target.checked })}
                      className="accent-[var(--primary)]"
                    />
                    View only (don't send keyboard, mouse or clipboard)
                  </label>
                  <label className="flex items-center gap-2 text-[var(--text-secondary)]">
                    <input
                      type="checkbox"
                      checked={Boolean(vncOptions.exclusive)}
                      onChange={(e) => setVncOptions({ ...vncOptions, exclusive: e.target.checked })}
                      className="accent-[var(--primary)]"
                    />
                    Exclusive session (ask the server to disconnect other viewers)
                  </label>
                </div>
              )}
            </div>

            {/* RIGHT COLUMN: AUTHENTICATION */}
            <div className="space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                Authentication
              </h3>

              <div>
                <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                  Auth Method
                </label>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMethod("password");
                      if (selectedKeyItem) setSelectedCredentialId("");
                    }}
                    className={`flex-1 flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-semibold transition ${
                      authMethod === "password"
                        ? "bg-[var(--primary)] text-[var(--on-primary)] shadow-sm"
                        : "bg-[var(--surface-container)] text-[var(--text-secondary)] border border-[var(--border)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-high)]"
                    }`}
                  >
                    <Lock size={13} /> Password
                  </button>
                  {protocol === "rdp" ? null : protocol === "vnc" ? (
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMethod("none");
                      setSelectedCredentialId("");
                    }}
                    className={`flex-1 flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-semibold transition ${
                      authMethod === "none"
                        ? "bg-[var(--primary)] text-[var(--on-primary)] shadow-sm"
                        : "bg-[var(--surface-container)] text-[var(--text-secondary)] border border-[var(--border)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-high)]"
                    }`}
                  >
                    <Unlock size={13} /> No Password
                  </button>
                  ) : (
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMethod("private_key");
                      if (selectedIdentityItem) setSelectedCredentialId("");
                    }}
                    className={`flex-1 flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-semibold transition ${
                      authMethod === "private_key"
                        ? "bg-[var(--primary)] text-[var(--on-primary)] shadow-sm"
                        : "bg-[var(--surface-container)] text-[var(--text-secondary)] border border-[var(--border)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-high)]"
                    }`}
                  >
                    <Key size={13} /> Key PEM
                  </button>
                  )}
                </div>
              </div>

              {authMethod === "none" ? (
                <p className="pt-1 text-[11px] text-[var(--text-muted)] leading-relaxed">
                  For VNC servers configured without authentication. Anyone who can reach the
                  server can see and control the desktop.
                </p>
              ) : authMethod === "password" ? (
                <div className="space-y-3 pt-1">
                  {/* Keychain Identity Selector */}
                  {availableIdentities.length > 0 && (
                    <div>
                      <label className="mb-1.5 flex items-center justify-between font-medium text-[var(--text-muted)]">
                        <span className="flex items-center gap-1.5">
                          <UserCheck size={12} className="text-[var(--tertiary)]" />
                          Keychain Identity
                        </span>
                        <span className="text-[10px] text-[var(--text-muted)]">
                          Reusable credentials
                        </span>
                      </label>
                      <CustomSelect
                        value={selectedCredentialId}
                        onChange={handleSelectCredential}
                        options={[
                          { value: "", label: "-- Custom one-off password --" },
                          ...availableIdentities.map((item) => ({
                            value: item.id,
                            label: item.name,
                            description: item.username ? `(${item.username})` : undefined,
                          })),
                        ]}
                      />
                    </div>
                  )}

                  {!selectedIdentityItem && (
                    <div>
                      <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                        Password
                      </label>
                      <div className="relative">
                        <input
                          type={showPassword ? "text" : "password"}
                          value={secret}
                          onChange={(e) => {
                            setSecret(e.target.value);
                            setShowPassword(true);
                          }}
                          disabled={passwordLoading}
                          placeholder={passwordLoading ? "Loading..." : protocol === "vnc" ? "VNC password..." : protocol === "rdp" ? "Windows / RDP password..." : "Server password (leave empty to be asked when connecting)"}
                          className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 pr-9 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:border-[var(--primary)] focus:outline-none transition-colors disabled:opacity-60"
                        />
                        <button
                          type="button"
                          onClick={handleTogglePassword}
                          disabled={passwordLoading}
                          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] disabled:opacity-50 transition-colors"
                          title={showPassword ? "Hide password" : "Show password"}
                        >
                          {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-3 pt-1">
                  {/* Keychain Key Dropdown */}
                  <div>
                    <label className="mb-1.5 flex items-center justify-between font-medium text-[var(--text-muted)]">
                      <span className="flex items-center gap-1.5">
                        <KeyRound size={13} className="text-[var(--primary)]" />
                        Keychain Key
                      </span>
                      <span className="text-[10px] text-[var(--text-muted)]">
                        Select from Keychain
                      </span>
                    </label>
                    <CustomSelect
                      value={selectedCredentialId}
                      onChange={handleSelectCredential}
                      options={[
                        {
                          value: "",
                          label: availableKeys.length > 0
                            ? "-- Select an SSH key from Keychain --"
                            : "-- No SSH keys in Keychain --",
                        },
                        ...availableKeys.map((item) => ({
                          value: item.id,
                          label: item.name,
                          description: `(${item.key_type || "KEY"})`,
                        })),
                      ]}
                    />
                  </div>

                  {/* If a Keychain key is selected: show preview & copy pubkey button */}
                  {selectedKeyItem ? (
                    <div className="rounded-xl border border-[var(--primary)]/30 bg-[var(--surface-container)] p-3 space-y-2.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[var(--secondary)]/15 text-[var(--secondary)]">
                            <Key size={14} />
                          </div>
                          <div>
                            <p className="text-xs font-semibold text-[var(--text-primary)]">
                              {selectedKeyItem.name}
                            </p>
                            <p className="text-[10px] text-[var(--text-muted)]">
                              Type {selectedKeyItem.key_type || "SSH"}
                              {selectedKeyItem.username && ` · ${selectedKeyItem.username}`}
                            </p>
                          </div>
                        </div>

                        {selectedKeyItem.public_key && (
                          <button
                            type="button"
                            onClick={() => handleCopyPublicKey(selectedKeyItem.public_key)}
                            className={`flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                              copied
                                ? "bg-[var(--success)] text-[var(--on-success)]"
                                : "bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-[var(--on-primary)]"
                            }`}
                          >
                            {copied ? (
                              <>
                                <Check size={12} /> Copied!
                              </>
                            ) : (
                              <>
                                <Copy size={12} /> Copy Public Key
                              </>
                            )}
                          </button>
                        )}
                      </div>

                      {selectedKeyItem.public_key && (
                        <div className="rounded-lg bg-[var(--canvas)] p-2 font-mono text-[11px] text-[var(--text-primary)] select-all break-all border border-[var(--border)] max-h-16 overflow-y-auto">
                          {selectedKeyItem.public_key}
                        </div>
                      )}

                      <p className="text-[11px] text-[var(--text-muted)]">
                        This host will authenticate using the{" "}
                        <strong className="text-[var(--text-primary)]">
                          {selectedKeyItem.name}
                        </strong>{" "}
                        private key from your Keychain.
                      </p>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-dashed border-[var(--border)] bg-[var(--surface-container)]/40 p-4 text-center">
                      <KeyRound size={22} className="mx-auto mb-2 text-[var(--text-muted)] opacity-50" />
                      <p className="text-xs font-medium text-[var(--text-secondary)]">
                        {availableKeys.length > 0
                          ? "Select an SSH key from Keychain above"
                          : "No SSH keys found in Keychain"}
                      </p>
                      <p className="mt-1 text-[11px] text-[var(--text-muted)] leading-relaxed">
                        To add, generate, or import SSH private keys, manage them in the{" "}
                        <strong className="text-[var(--text-primary)]">Keychain</strong> menu.
                      </p>
                      {onOpenKeychain && (
                        <button
                          type="button"
                          onClick={() => {
                            closeHostModal();
                            onOpenKeychain();
                          }}
                          className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-[var(--primary)]/15 px-3 py-1.5 text-xs font-semibold text-[var(--primary)] hover:bg-[var(--primary)]/25 border border-[var(--primary)]/30 transition-colors"
                        >
                          <KeyRound size={13} />
                          <span>Go to Keychain</span>
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* OS ICON OVERRIDE */}
          <div className="border-t border-[var(--border)] pt-4">
            <div className="flex items-start gap-4">
              <div className="flex flex-col items-center gap-1.5 shrink-0">
                {/* Live preview of current selection */}
                {osIcon ? (
                  <DistroBadge
                    host={{ os_icon: osIcon } as any}
                    size="lg"
                  />
                ) : (
                  <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-dashed border-[var(--border)] bg-[var(--surface-container)] text-[var(--text-muted)]">
                    <Cpu size={18} />
                  </div>
                )}
                <span className="text-[10px] text-[var(--text-muted)] font-mono">preview</span>
              </div>

              <div className="flex-1 min-w-0">
                <label className="mb-1.5 block font-medium text-[var(--text-muted)]">
                  OS / Distro Icon
                </label>
                <CustomSelect
                  value={osIcon}
                  onChange={setOsIcon}
                  options={DISTRO_OPTIONS.map((opt) => ({
                    value: opt.id,
                    label: opt.label,
                  }))}
                />
                <p className="mt-1 text-[11px] text-[var(--text-muted)] leading-relaxed">
                  Leave on <span className="font-mono">Auto-detect</span> — the icon will be set automatically the first time you SSH into this host.
                </p>
              </div>
            </div>
          </div>

          {/* FOOTER ACTIONS */}
          <div className="flex items-center justify-end gap-2.5 pt-4 border-t border-[var(--border)]">
            <button
              type="button"
              onClick={closeHostModal}
              className="rounded-xl px-4 py-2 text-xs font-medium text-[var(--text-muted)] hover:bg-[var(--surface-high)] hover:text-[var(--text-primary)] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-xl bg-[var(--primary)] px-5 py-2 text-xs font-semibold text-[var(--on-primary)] transition hover:bg-[var(--primary-hover)] disabled:opacity-50 shadow-sm"
            >
              {submitting ? "Saving..." : editingHost ? "Update Host" : "Save Host"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
