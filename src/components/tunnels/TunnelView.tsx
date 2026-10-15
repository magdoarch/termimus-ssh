import { useEffect, useState, useCallback, memo } from "react";
import {
  ArrowLeftRight,
  Plus,
  Play,
  Square,
  Pencil,
  Trash2,
  Server,
  Loader2,
  AlertCircle,
  Copy,
  Check,
  RefreshCw,
} from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { useTunnelStore } from "../../stores/useTunnelStore";
import { useHostStore } from "../../stores/useHostStore";
import { useConfirmStore } from "../../stores/useConfirmStore";
import { TunnelModal } from "./TunnelModal";
import { PortForwardRule, Host } from "../../lib/api";
import { copyText } from "../../lib/clipboard";
import { describeRoute, forwardTypeInfo } from "../../lib/tunnelRoute";

export function TunnelView() {
  const {
    rules,
    activeRuleIds,
    ruleErrors,
    isLoading,
    error,
    startingRuleId,
    refresh,
    toggleTunnel,
    openCreateModal,
    openEditModal,
    deleteRule,
  } = useTunnelStore(
    useShallow((s) => ({
      rules: s.rules,
      activeRuleIds: s.activeRuleIds,
      ruleErrors: s.ruleErrors,
      isLoading: s.isLoading,
      error: s.error,
      startingRuleId: s.startingRuleId,
      refresh: s.refresh,
      toggleTunnel: s.toggleTunnel,
      openCreateModal: s.openCreateModal,
      openEditModal: s.openEditModal,
      deleteRule: s.deleteRule,
    }))
  );

  const hosts = useHostStore((s) => s.hosts);

  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    type: "rule" | "background";
    rule?: PortForwardRule;
  } | null>(null);

  const [copyToast, setCopyToast] = useState<string | null>(null);

  const showCopyToast = useCallback((msg: string) => {
    setCopyToast(msg);
    setTimeout(() => {
      setCopyToast((prev) => (prev === msg ? null : prev));
    }, 1800);
  }, []);

  const handleRuleContextMenu = useCallback((e: React.MouseEvent, rule: PortForwardRule) => {
    e.preventDefault();
    e.stopPropagation();
    const x = Math.min(e.clientX, window.innerWidth - 220);
    const y = Math.min(e.clientY, window.innerHeight - 280);
    setContextMenu({ x, y, type: "rule", rule });
  }, []);

  const handleBackgroundContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const x = Math.min(e.clientX, window.innerWidth - 220);
    const y = Math.min(e.clientY, window.innerHeight - 150);
    setContextMenu({ x, y, type: "background" });
  }, []);

  useEffect(() => {
    if (!contextMenu) return;
    const handleClose = () => setContextMenu(null);
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setContextMenu(null);
    };
    window.addEventListener("pointerdown", handleClose);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("pointerdown", handleClose);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [contextMenu]);

  useEffect(() => {
    if (rules.length === 0) {
      refresh();
    }
  }, [rules.length, refresh]);

  const handleDelete = useCallback(
    (ruleId: string, ruleLabel?: string) => {
      useConfirmStore.getState().confirm({
        title: "Delete Port Forwarding Rule",
        message: `Are you sure you want to delete ${ruleLabel ? `"${ruleLabel}"` : "this tunnel rule"}? This action cannot be undone.`,
        confirmLabel: "Delete Rule",
        isDanger: true,
        onConfirm: async () => {
          await deleteRule(ruleId);
        },
      });
    },
    [deleteRule]
  );

  return (
    <div
      onContextMenu={handleBackgroundContextMenu}
      className="flex h-full w-full flex-col overflow-hidden bg-[var(--canvas)] p-4 select-none"
    >
      <TunnelModal />

      {/* Header */}
      <div className="mb-4 flex items-center justify-between border-b border-[var(--border)] pb-3">
        <div>
          <h2 className="text-base font-semibold text-[var(--text-primary)] flex items-center gap-2">
            <ArrowLeftRight size={18} className="text-[var(--accent)]" />
            Port Forwarding / SSH Tunnels
          </h2>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">
            Local, remote and dynamic (SOCKS) forwarding through SSH tunnels.
          </p>
        </div>
        <button
          onClick={openCreateModal}
          className="flex items-center gap-1.5 rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-medium text-white transition hover:bg-[var(--accent-hover)]"
        >
          <Plus size={14} /> New Tunnel
        </button>
      </div>

      {error && (
        <div className="mb-4 flex items-center gap-2 rounded-md border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-3 py-2 text-xs text-[var(--danger)]">
          <AlertCircle size={14} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Rules List */}
      <div className="flex-1 overflow-y-auto">
        {isLoading && rules.length === 0 ? (
          <div className="flex h-40 items-center justify-center text-xs text-[var(--text-muted)]">
            <Loader2 size={16} className="animate-spin mr-2 text-[var(--accent)]" />
            Loading rules...
          </div>
        ) : rules.length === 0 ? (
          <div className="flex h-60 flex-col items-center justify-center text-center text-[var(--text-muted)]">
            <ArrowLeftRight size={38} className="mb-2 opacity-30" />
            <p className="text-sm font-medium">No port forwarding rules yet</p>
            <p className="text-xs mt-1 max-w-sm">
              Create a rule to access remote databases, APIs, or web servers via localhost.
            </p>
            <button
              onClick={openCreateModal}
              className="mt-4 rounded-md border border-[var(--border)] bg-[var(--card)] px-3 py-1.5 text-xs text-[var(--text-primary)] hover:bg-[var(--border)]"
            >
              Add First Rule
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {rules.map((rule) => {
              const host = hosts.find((h) => h.id === rule.host_id);
              const isActive = activeRuleIds.has(rule.id);
              const isBusy = startingRuleId === rule.id;

              return (
                <TunnelCard
                  key={rule.id}
                  rule={rule}
                  host={host}
                  isActive={isActive}
                  isBusy={isBusy}
                  stopError={ruleErrors[rule.id]}
                  onToggle={toggleTunnel}
                  onEdit={openEditModal}
                  onDelete={handleDelete}
                  onContextMenu={handleRuleContextMenu}
                />
              );
            })}
          </div>
        )}
      </div>

      {/* Right-Click Context Menu */}
      {contextMenu && (
        <div
          className="fixed z-50 min-w-[210px] rounded-xl border border-[var(--border)] bg-[var(--surface-high)]/95 p-1 text-xs text-[var(--text-primary)] shadow-2xl backdrop-blur-md select-none animate-in fade-in zoom-in-95 duration-75"
          style={{ left: `${contextMenu.x}px`, top: `${contextMenu.y}px` }}
          onPointerDown={(e) => e.stopPropagation()}
        >
          {contextMenu.type === "rule" && contextMenu.rule ? (
            <>
              {/* Start/Stop Tunnel */}
              <button
                onClick={() => {
                  toggleTunnel(contextMenu.rule!);
                  setContextMenu(null);
                }}
                className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-[var(--primary)] hover:text-[var(--on-primary)] transition-colors group"
              >
                {activeRuleIds.has(contextMenu.rule.id) ? (
                  <>
                    <Square size={13} />
                    <span>Stop Tunnel</span>
                  </>
                ) : (
                  <>
                    <Play size={13} />
                    <span>Start Tunnel</span>
                  </>
                )}
              </button>

              <div className="my-1 h-[1px] bg-[var(--border)]" />

              {/* Copy Listen Address */}
              <button
                onClick={async () => {
                  await copyText(describeRoute(contextMenu.rule!).listen);
                  showCopyToast("Copied listen address");
                  setContextMenu(null);
                }}
                className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-[var(--surface-container)] hover:text-[var(--text-primary)] transition-colors group"
              >
                <Copy size={13} />
                <span>{contextMenu.rule.forward_type === "dynamic" ? "Copy Proxy Address" : "Copy Listen Address"}</span>
              </button>

              {/* Copy Destination Address (dynamic forwards have none) */}
              {contextMenu.rule.forward_type !== "dynamic" && (
                <button
                  onClick={async () => {
                    await copyText(describeRoute(contextMenu.rule!).target ?? "");
                    showCopyToast("Copied destination address");
                    setContextMenu(null);
                  }}
                  className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-[var(--surface-container)] hover:text-[var(--text-primary)] transition-colors group"
                >
                  <Copy size={13} />
                  <span>Copy Destination Address</span>
                </button>
              )}

              <div className="my-1 h-[1px] bg-[var(--border)]" />

              {/* Edit */}
              <button
                onClick={() => {
                  openEditModal(contextMenu.rule!);
                  setContextMenu(null);
                }}
                disabled={activeRuleIds.has(contextMenu.rule.id)}
                className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-[var(--surface-container)] hover:text-[var(--text-primary)] transition-colors group disabled:opacity-40 disabled:pointer-events-none"
              >
                <Pencil size={13} />
                <span>Edit Rule</span>
              </button>

              {/* Delete */}
              <button
                onClick={() => {
                  handleDelete(contextMenu.rule!.id, contextMenu.rule!.label);
                  setContextMenu(null);
                }}
                disabled={activeRuleIds.has(contextMenu.rule.id)}
                className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-[var(--danger)] hover:text-white transition-colors group disabled:opacity-40 disabled:pointer-events-none"
              >
                <Trash2 size={13} />
                <span>Delete Rule</span>
              </button>
            </>
          ) : (
            <>
              {/* New Rule */}
              <button
                onClick={() => {
                  openCreateModal();
                  setContextMenu(null);
                }}
                className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-[var(--primary)] hover:text-[var(--on-primary)] transition-colors group"
              >
                <Plus size={13} />
                <span>New Port Forward Rule</span>
              </button>

              <button
                onClick={() => {
                  refresh();
                  setContextMenu(null);
                }}
                className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-[var(--surface-container)] hover:text-[var(--text-primary)] transition-colors group"
              >
                <RefreshCw size={13} />
                <span>Refresh Rules</span>
              </button>
            </>
          )}
        </div>
      )}

      {/* Copy Toast Notification */}
      {copyToast && (
        <div className="fixed top-11 right-3.5 z-50 flex items-center gap-2 rounded-lg border border-[var(--primary)]/40 bg-[var(--surface-high)]/95 px-3 py-1.5 text-xs font-mono font-medium text-[var(--primary)] shadow-2xl backdrop-blur-md animate-in fade-in slide-in-from-top-2 duration-150 pointer-events-none">
          <Check size={13} className="text-[var(--primary)] shrink-0" />
          <span>{copyToast}</span>
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// MEMOIZED TUNNEL CARD COMPONENT
// ══════════════════════════════════════════════════════════════════════════════

interface TunnelCardProps {
  rule: PortForwardRule;
  host: Host | undefined;
  isActive: boolean;
  isBusy: boolean;
  /** Why the tunnel stopped on its own, if it did */
  stopError?: string;
  onToggle: (rule: PortForwardRule) => void;
  onEdit: (rule: PortForwardRule) => void;
  onDelete: (id: string, label?: string) => void;
  onContextMenu?: (e: React.MouseEvent, rule: PortForwardRule) => void;
}

const TunnelCard = memo(function TunnelCard({
  rule,
  host,
  isActive,
  isBusy,
  stopError,
  onToggle,
  onEdit,
  onDelete,
  onContextMenu,
}: TunnelCardProps) {
  const route = describeRoute(rule);
  const type = forwardTypeInfo(rule.forward_type);
  return (
    <div
      onContextMenu={(e) => onContextMenu?.(e, rule)}
      className={`flex flex-col rounded-xl border p-4 transition-colors shadow-xs ${
        isActive
          ? "border-[var(--success)]/40 bg-[var(--success)]/5 shadow-md shadow-[var(--success)]/5"
          : "border-[var(--border)] bg-[var(--card)] hover:border-[var(--border)]/80"
      }`}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={`h-2.5 w-2.5 shrink-0 rounded-full ${
              isActive
                ? "bg-[var(--success)] animate-pulse"
                : "bg-[var(--text-muted)]/40"
            }`}
          />
          <h3 className="truncate text-sm font-semibold text-[var(--text-primary)]">
            {rule.label}
          </h3>
          <span
            className="shrink-0 rounded border border-[var(--border)] bg-[var(--surface-high)] px-1.5 py-0.5 font-mono text-[9px] text-[var(--text-muted)]"
            title={type.description}
          >
            {type.flag} {type.label}
          </span>
        </div>

        <div className="flex shrink-0 items-center gap-1">
          <button
            onClick={() => onEdit(rule)}
            disabled={isActive}
            title="Edit rule"
            className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--border)] hover:text-[var(--text-primary)] disabled:opacity-30"
          >
            <Pencil size={13} />
          </button>
          <button
            onClick={() => onDelete(rule.id, rule.label)}
            disabled={isActive}
            title="Delete rule"
            className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--danger)]/20 hover:text-[var(--danger)] disabled:opacity-30 transition"
          >
            <Trash2 size={13} />
          </button>
        </div>
      </div>

      {/* Endpoint Routing Diagram */}
      <div className="rounded-lg border border-[var(--border)] bg-[var(--background)] p-2.5 text-xs mb-3 space-y-1 font-mono">
        <div className="flex items-center justify-between gap-2 text-[var(--text-muted)]">
          <span className="shrink-0">{route.listenLabel}:</span>
          <span className="truncate text-[var(--accent)] font-semibold">{route.listen}</span>
        </div>
        <div className="flex items-center justify-between gap-2 text-[var(--text-muted)]">
          <span className="shrink-0">{route.targetLabel}:</span>
          <span className="truncate text-[var(--text-primary)]">
            {route.target ?? <span className="text-[var(--text-muted)] italic">any (chosen by each app)</span>}
          </span>
        </div>
      </div>

      {stopError && !isActive && (
        <div className="mb-3 flex items-start gap-1.5 rounded-md border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-2 py-1.5 text-[11px] text-[var(--danger)]">
          <AlertCircle size={12} className="mt-0.5 shrink-0" />
          <span>Stopped: {stopError}</span>
        </div>
      )}

      {/* Via Host */}
      <div className="flex min-w-0 items-center gap-1.5 text-xs text-[var(--text-muted)] mb-4">
        <Server size={12} className="shrink-0" />
        <span className="truncate">
          via {host ? host.label : "Unknown host"}
        </span>
      </div>

      {/* Toggle Button */}
      <div className="mt-auto pt-2 border-t border-[var(--border)]/50">
        <button
          onClick={() => onToggle(rule)}
          disabled={isBusy}
          className={`flex w-full items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-semibold transition ${
            isActive
              ? "bg-[var(--danger)]/15 text-[var(--danger)] hover:bg-[var(--danger)]/25"
              : "bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)]"
          } disabled:opacity-50`}
        >
          {isBusy ? (
            <>
              <Loader2 size={13} className="animate-spin" />
              <span>{isActive ? "Stopping..." : "Starting..."}</span>
            </>
          ) : isActive ? (
            <>
              <Square size={13} />
              <span>Stop Tunnel</span>
            </>
          ) : (
            <>
              <Play size={13} />
              <span>Start Tunnel</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
});
