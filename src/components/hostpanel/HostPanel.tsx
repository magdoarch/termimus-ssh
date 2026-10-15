import { useEffect } from "react";
import { Container, Gauge, X } from "lucide-react";
import { api } from "../../lib/api";
import { useShallow } from "zustand/react/shallow";
import { useHostPanelStore, type HostPanelTab } from "../../stores/useHostPanelStore";
import { useHostStore } from "../../stores/useHostStore";
import { HostStatsView } from "./HostStatsView";
import { DockerView } from "./DockerView";

const TABS: { id: HostPanelTab; label: string; icon: typeof Gauge }[] = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "docker", label: "Docker", icon: Container },
];

/** Server dashboard of an SSH host, over its (shared) SSH connection. */
export function HostPanel() {
  const { hostId, tab, setTab, close } = useHostPanelStore(
    useShallow((s) => ({ hostId: s.hostId, tab: s.tab, setTab: s.setTab, close: s.close }))
  );
  const host = useHostStore((s) => s.hosts.find((h) => h.id === hostId));

  // One login for everything the panel does while it is open.
  useEffect(() => {
    if (!hostId) return;
    const leaseId = `panel-${hostId}-${Math.random().toString(36).slice(2, 8)}`;
    api.holdHostConnection(hostId, leaseId).catch(() => {});
    return () => {
      api.releaseHostConnection(leaseId).catch(() => {});
    };
  }, [hostId]);

  useEffect(() => {
    if (!hostId) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") close();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [hostId, close]);

  if (!hostId || !host) return null;

  return (
    <div
      onPointerDown={(e) => {
        if (e.target === e.currentTarget) close();
      }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
    >
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] shadow-2xl">
        <div className="flex items-center justify-between gap-3 border-b border-[var(--border)] px-5 py-3">
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-[var(--text-primary)]">{host.label}</h2>
            <p className="truncate font-mono text-[11px] text-[var(--text-muted)]">
              {host.username}@{host.address}
              {host.port !== 22 && `:${host.port}`}
            </p>
          </div>
          <div className="flex items-center gap-1">
            {TABS.length > 1 &&
              TABS.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setTab(id)}
                  className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs transition-colors ${
                    tab === id
                      ? "bg-[var(--surface-high)] font-semibold text-[var(--primary)]"
                      : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <Icon size={13} /> {label}
                </button>
              ))}
            <button
              type="button"
              onClick={close}
              className="ml-2 rounded p-1 text-[var(--text-muted)] hover:bg-[var(--border)] hover:text-[var(--text-primary)]"
            >
              <X size={16} />
            </button>
          </div>
        </div>
        <div className="min-h-0 overflow-y-auto p-5">
          {tab === "overview" && <HostStatsView hostId={host.id} />}
          {tab === "docker" && <DockerView hostId={host.id} />}
        </div>
      </div>
    </div>
  );
}
