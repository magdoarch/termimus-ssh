import { useState, useEffect } from "react";
import { X, ArrowLeftRight, ShieldAlert } from "lucide-react";
import { useTunnelStore } from "../../stores/useTunnelStore";
import { useHostStore } from "../../stores/useHostStore";
import { isSshHost, PortForwardInput } from "../../lib/api";
import { FORWARD_TYPES, ForwardType, forwardTypeInfo, isLoopbackHost } from "../../lib/tunnelRoute";
import { CustomSelect } from "../ui/CustomSelect";

const inputClass =
  "w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-2.5 py-1.5 text-xs font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:border-[var(--primary)] focus:outline-none transition-colors";

/** Starting values when the type of a new rule is picked. */
const TYPE_DEFAULTS: Record<ForwardType, { localAddress: string; localPort: number; remoteAddress: string; remotePort: number }> = {
  local: { localAddress: "127.0.0.1", localPort: 8080, remoteAddress: "127.0.0.1", remotePort: 80 },
  remote: { localAddress: "127.0.0.1", localPort: 3000, remoteAddress: "127.0.0.1", remotePort: 8080 },
  dynamic: { localAddress: "127.0.0.1", localPort: 1080, remoteAddress: "", remotePort: 0 },
};

function EndpointFields({
  title,
  hint,
  hostLabel,
  host,
  onHost,
  hostPlaceholder,
  hostRequired,
  port,
  onPort,
}: {
  title: string;
  hint?: React.ReactNode;
  hostLabel: string;
  host: string;
  onHost: (v: string) => void;
  hostPlaceholder: string;
  hostRequired?: boolean;
  port: number;
  onPort: (v: number) => void;
}) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-container)]/40 p-3.5 space-y-3">
      <div className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">{title}</div>
      <div className="grid grid-cols-3 gap-2">
        <div className="col-span-2">
          <label className="mb-1 block text-[11px] text-[var(--text-muted)]">
            {hostLabel}
            {hostRequired ? " *" : ""}
          </label>
          <input
            type="text"
            required={hostRequired}
            value={host}
            onChange={(e) => onHost(e.target.value)}
            placeholder={hostPlaceholder}
            className={inputClass}
          />
        </div>
        <div>
          <label className="mb-1 block text-[11px] text-[var(--text-muted)]">Port *</label>
          <input
            type="number"
            required
            min={1}
            max={65535}
            value={port || ""}
            onChange={(e) => onPort(Number(e.target.value))}
            className={inputClass}
          />
        </div>
      </div>
      {hint && <p className="text-[11px] leading-relaxed text-[var(--text-muted)]">{hint}</p>}
    </div>
  );
}

export function TunnelModal() {
  const { isModalOpen, editingRule, closeModal, saveRule } = useTunnelStore();
  const { hosts } = useHostStore();

  const [label, setLabel] = useState("");
  const [hostId, setHostId] = useState("");
  const [forwardType, setForwardType] = useState<ForwardType>("local");
  const [localAddress, setLocalAddress] = useState("127.0.0.1");
  const [localPort, setLocalPort] = useState(8080);
  const [remoteAddress, setRemoteAddress] = useState("127.0.0.1");
  const [remotePort, setRemotePort] = useState(80);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function applyDefaults(type: ForwardType) {
    const d = TYPE_DEFAULTS[type];
    setLocalAddress(d.localAddress);
    setLocalPort(d.localPort);
    setRemoteAddress(d.remoteAddress);
    setRemotePort(d.remotePort);
  }

  useEffect(() => {
    if (editingRule) {
      setLabel(editingRule.label);
      setHostId(editingRule.host_id);
      setForwardType(editingRule.forward_type);
      setLocalAddress(editingRule.local_address);
      setLocalPort(editingRule.local_port);
      setRemoteAddress(editingRule.remote_address);
      setRemotePort(editingRule.remote_port);
    } else {
      setLabel("");
      setHostId(hosts.find(isSshHost)?.id ?? "");
      setForwardType("local");
      applyDefaults("local");
    }
    setError(null);
  }, [editingRule, isModalOpen, hosts]);

  if (!isModalOpen) return null;

  function handleTypeChange(type: ForwardType) {
    if (type === forwardType) return;
    setForwardType(type);
    // Keep what the user typed when editing; a new rule starts from sensible values.
    if (!editingRule) applyDefaults(type);
  }

  const validPort = (p: number) => Number.isInteger(p) && p >= 1 && p <= 65535;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!label.trim()) {
      setError("Label is required");
      return;
    }
    if (!hostId) {
      setError("Please select an SSH host");
      return;
    }
    if (!validPort(localPort) || (forwardType !== "dynamic" && !validPort(remotePort))) {
      setError("Ports must be between 1 and 65535");
      return;
    }

    const isDynamic = forwardType === "dynamic";
    const input: PortForwardInput = {
      host_id: hostId,
      label: label.trim(),
      forward_type: forwardType,
      local_address: localAddress.trim() || "127.0.0.1",
      local_port: Number(localPort),
      // Unused for dynamic forwards (each app picks its destination).
      remote_address: isDynamic ? "" : remoteAddress.trim() || "127.0.0.1",
      remote_port: isDynamic ? 0 : Number(remotePort),
    };

    setSubmitting(true);
    try {
      await saveRule(input, editingRule?.id);
      closeModal();
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  }

  // Listening on a non-loopback address of this computer exposes the tunnel
  // to the local network.
  const exposedLocally = forwardType !== "remote" && !isLoopbackHost(localAddress);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 select-none">
      <div className="w-full max-w-md max-h-[90vh] overflow-y-auto rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between border-b border-[var(--border)] pb-3">
          <div className="flex items-center gap-2">
            <ArrowLeftRight size={18} className="text-[var(--primary)]" />
            <h2 className="text-base font-semibold text-[var(--text-primary)]">
              {editingRule ? "Edit Port Forwarding" : "New Port Forwarding"}
            </h2>
          </div>
          <button
            onClick={closeModal}
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

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="mb-1.5 block font-medium text-[var(--text-muted)]">Rule Name / Label *</label>
            <input
              type="text"
              required
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Postgres DB, Dev server, Browse via bastion"
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] px-3 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)]/50 focus:border-[var(--primary)] focus:outline-none transition-colors"
            />
          </div>

          <div>
            <label className="mb-1.5 block font-medium text-[var(--text-muted)]">SSH Host *</label>
            <CustomSelect
              value={hostId}
              onChange={setHostId}
              placeholder="Select SSH server..."
              options={[
                { value: "", label: "Select SSH server..." },
                ...hosts.filter(isSshHost).map((h) => ({
                  value: h.id,
                  label: h.label,
                  description: `(${h.username}@${h.address}:${h.port})`,
                })),
              ]}
            />
          </div>

          <div>
            <label className="mb-1.5 block font-medium text-[var(--text-muted)]">Type</label>
            <div className="flex gap-1.5" role="radiogroup" aria-label="Forwarding type">
              {FORWARD_TYPES.map((t) => (
                <button
                  key={t.value}
                  type="button"
                  role="radio"
                  aria-checked={forwardType === t.value}
                  onClick={() => handleTypeChange(t.value)}
                  title={t.description}
                  className={`flex flex-1 flex-col items-center rounded-lg border py-1.5 transition ${
                    forwardType === t.value
                      ? "border-[var(--primary)] bg-[var(--primary)]/10 text-[var(--primary)]"
                      : "border-[var(--border)] bg-[var(--surface-container)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <span className="text-xs font-semibold">{t.label}</span>
                  <span className="font-mono text-[10px] opacity-70">ssh {t.flag}</span>
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--text-muted)]">
              {forwardTypeInfo(forwardType).description}
            </p>
          </div>

          {forwardType === "local" && (
            <>
              <EndpointFields
                title="Listen on this computer"
                hostLabel="Bind IP"
                host={localAddress}
                onHost={setLocalAddress}
                hostPlaceholder="127.0.0.1"
                port={localPort}
                onPort={setLocalPort}
              />
              <EndpointFields
                title="Destination (reached from the SSH server)"
                hostLabel="Host"
                host={remoteAddress}
                onHost={setRemoteAddress}
                hostPlaceholder="127.0.0.1 or db.internal"
                hostRequired
                port={remotePort}
                onPort={setRemotePort}
              />
            </>
          )}

          {forwardType === "remote" && (
            <>
              <EndpointFields
                title="Listen on the SSH server"
                hostLabel="Bind address"
                host={remoteAddress}
                onHost={setRemoteAddress}
                hostPlaceholder="127.0.0.1"
                port={remotePort}
                onPort={setRemotePort}
                hint={
                  <>
                    127.0.0.1 makes the port reachable only on the server itself. Other addresses
                    (e.g. 0.0.0.0) need <span className="font-mono">GatewayPorts</span> enabled in the
                    server's sshd_config.
                  </>
                }
              />
              <EndpointFields
                title="Destination (reached from this computer)"
                hostLabel="Host"
                host={localAddress}
                onHost={setLocalAddress}
                hostPlaceholder="127.0.0.1"
                hostRequired
                port={localPort}
                onPort={setLocalPort}
              />
            </>
          )}

          {forwardType === "dynamic" && (
            <EndpointFields
              title="SOCKS proxy on this computer"
              hostLabel="Bind IP"
              host={localAddress}
              onHost={setLocalAddress}
              hostPlaceholder="127.0.0.1"
              port={localPort}
              onPort={setLocalPort}
              hint={
                <>
                  Set your browser or app to use the SOCKS5 proxy{" "}
                  <span className="font-mono">
                    {localAddress.trim() || "127.0.0.1"}:{localPort || "port"}
                  </span>
                  . Host names are resolved by the server (SOCKS5h); SOCKS4/4a also work.
                </>
              }
            />
          )}

          {exposedLocally && (
            <div className="flex items-start gap-2 rounded-md border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-2.5 py-2 text-[11px] text-[var(--warning)]">
              <ShieldAlert size={13} className="mt-0.5 shrink-0" />
              <span>
                {forwardType === "dynamic"
                  ? "Anyone on your network could use this proxy (it has no password) to reach the server's network. Prefer 127.0.0.1."
                  : "Other devices on your network can connect to this port. Prefer 127.0.0.1 unless you need that."}
              </span>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border)]">
            <button
              type="button"
              onClick={closeModal}
              className="rounded-xl border border-[var(--border)] bg-[var(--surface-high)] px-4 py-2 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--surface-highest)] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-xl bg-[var(--primary)] px-4 py-2 text-xs font-semibold text-[var(--on-primary)] hover:bg-[var(--primary-hover)] transition-colors shadow-sm disabled:opacity-50"
            >
              {submitting ? "Saving..." : editingRule ? "Update Rule" : "Create Rule"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
