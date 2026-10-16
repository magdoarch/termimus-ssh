import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  Copy,
  LoaderCircle,
  Pause,
  Play,
  RotateCw,
  ScrollText,
  Search,
  Square,
  SquareTerminal,
  Trash2,
} from "lucide-react";
import { api, type DockerAction, type DockerContainer, type DockerContainerStats } from "../../lib/api";
import { copyText } from "../../lib/clipboard";
import { useConfirmStore } from "../../stores/useConfirmStore";
import { useHostPanelStore } from "../../stores/useHostPanelStore";
import { useHostStore } from "../../stores/useHostStore";
import { useSessionStore } from "../../stores/useSessionStore";

const REFRESH_MS = 5000;

const STATE_COLOR: Record<string, string> = {
  running: "var(--success)",
  paused: "var(--warning)",
  restarting: "var(--warning)",
};

function IconButton({
  title,
  onClick,
  disabled,
  danger,
  children,
}: {
  title: string;
  onClick: () => void;
  disabled?: boolean;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-md p-1.5 transition-colors disabled:opacity-30 ${
        danger
          ? "text-[var(--text-muted)] hover:bg-[var(--danger)]/15 hover:text-[var(--danger)]"
          : "text-[var(--text-muted)] hover:bg-[var(--surface-high)] hover:text-[var(--text-primary)]"
      }`}
    >
      {children}
    </button>
  );
}

function ContainerLogs({
  hostId,
  container,
  sudo,
  onBack,
}: {
  hostId: string;
  container: DockerContainer;
  sudo: boolean;
  onBack: () => void;
}) {
  const [tail, setTail] = useState(500);
  const [follow, setFollow] = useState(true);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);
  const fetching = useRef(false);

  const load = useCallback(async () => {
    // One fetch at a time: a slow one must not land after a newer one.
    if (fetching.current) return;
    fetching.current = true;
    try {
      setText(await api.dockerLogs(hostId, container.id, tail, sudo));
      setError(null);
    } catch (e) {
      setError(String(e));
      setFollow(false);
    } finally {
      fetching.current = false;
    }
  }, [hostId, container.id, tail, sudo]);

  useEffect(() => {
    load();
    if (!follow) return;
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
  }, [load, follow]);

  useEffect(() => {
    if (follow && preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight;
  }, [text, follow]);

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <button
          type="button"
          onClick={onBack}
          className="flex items-center gap-1 rounded-lg px-2 py-1 text-[var(--text-muted)] hover:bg-[var(--surface-high)] hover:text-[var(--text-primary)]"
        >
          <ArrowLeft size={13} /> Containers
        </button>
        <span className="font-semibold text-[var(--text-primary)]">Logs of {container.name}</span>
        <div className="ml-auto flex items-center gap-2">
          <select
            value={tail}
            onChange={(e) => setTail(Number(e.target.value))}
            className="rounded-md border border-[var(--border)] bg-[var(--surface-container)] px-2 py-1 text-xs text-[var(--text-primary)]"
          >
            {[200, 500, 2000, 10000].map((n) => (
              <option key={n} value={n}>
                last {n} lines
              </option>
            ))}
          </select>
          <label className="flex items-center gap-1.5 text-[var(--text-muted)]">
            <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} className="accent-[var(--primary)]" />
            Follow
          </label>
          <IconButton title="Copy logs" onClick={() => text && copyText(text)}>
            <Copy size={13} />
          </IconButton>
        </div>
      </div>
      {error && <p className="text-xs text-[var(--danger)]">{error}</p>}
      <pre
        ref={preRef}
        className="min-h-[300px] flex-1 overflow-auto rounded-lg border border-[var(--border)] bg-[var(--canvas)] p-3 font-mono text-[11px] leading-relaxed text-[var(--text-secondary)] whitespace-pre-wrap break-all select-text"
      >
        {text === null ? "Loading…" : text || "(no output)"}
      </pre>
    </div>
  );
}

/** Docker containers on an SSH host: state, resource use, actions, logs, shells. */
export function DockerView({ hostId }: { hostId: string }) {
  const host = useHostStore((s) => s.hosts.find((h) => h.id === hostId));
  const [containers, setContainers] = useState<DockerContainer[] | null>(null);
  const [sudo, setSudo] = useState(false);
  const [stats, setStats] = useState<Record<string, DockerContainerStats>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [logsFor, setLogsFor] = useState<DockerContainer | null>(null);
  const [filter, setFilter] = useState("");
  // Stops after a failure (e.g. a cancelled login) until Refresh, so the
  // panel doesn't ask for a password or code again every few seconds.
  const [polling, setPolling] = useState(true);
  const loading = useRef(false);

  const refresh = useCallback(async () => {
    if (loading.current) return;
    loading.current = true;
    try {
      const list = await api.dockerList(hostId);
      setContainers(list.containers);
      setSudo(list.sudo);
      setError(null);
      if (list.containers.some((c) => c.state === "running")) {
        // Slower (docker samples for a moment): fill in when it arrives.
        api
          .dockerStats(hostId, list.sudo)
          .then((all) => setStats(Object.fromEntries(all.map((s) => [s.id, s]))))
          .catch(() => {});
      }
    } catch (e) {
      setError(String(e));
      setPolling(false);
    } finally {
      loading.current = false;
    }
  }, [hostId]);

  useEffect(() => {
    if (!polling) return;
    refresh();
    const timer = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(timer);
  }, [refresh, polling]);

  const refreshNow = () => {
    setError(null);
    if (polling) refresh();
    else setPolling(true);
  };

  async function run(container: DockerContainer, action: DockerAction) {
    setBusy(container.id);
    try {
      await api.dockerAction(hostId, container.id, action, sudo);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  function remove(container: DockerContainer) {
    useConfirmStore.getState().confirm({
      title: "Remove container",
      message: `Remove the stopped container "${container.name}"? Its writable layer is deleted; volumes stay.`,
      confirmLabel: "Remove",
      isDanger: true,
      onConfirm: () => run(container, "remove"),
    });
  }

  function openShell(container: DockerContainer) {
    if (!host) return;
    const command = `${sudo ? "sudo -n " : ""}docker exec -it ${container.id} sh -c "command -v bash >/dev/null 2>&1 && exec bash || exec sh"`;
    useSessionStore.getState().openSession(host, true, { command, label: `${container.name} @ ${host.label}` });
    useHostPanelStore.getState().close();
  }

  if (logsFor) {
    return <ContainerLogs hostId={hostId} container={logsFor} sudo={sudo} onBack={() => setLogsFor(null)} />;
  }

  if (containers === null) {
    return (
      <div className="flex min-h-[240px] flex-col items-center justify-center gap-3 text-xs text-[var(--text-muted)]">
        {error ? (
          <>
            <p className="max-w-md text-center text-[var(--danger)]">{error}</p>
            <button
              type="button"
              onClick={refreshNow}
              className="flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-high)] px-3 py-1.5 text-[var(--text-primary)] hover:bg-[var(--surface-highest)]"
            >
              <RotateCw size={12} /> Try again
            </button>
          </>
        ) : (
          <span className="flex items-center gap-2">
            <LoaderCircle size={14} className="animate-spin" /> Asking Docker…
          </span>
        )}
      </div>
    );
  }

  const query = filter.trim().toLowerCase();
  const shown = containers.filter(
    (c) => !query || c.name.toLowerCase().includes(query) || c.image.toLowerCase().includes(query)
  );
  const running = containers.filter((c) => c.state === "running").length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <div className="relative w-56">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by name or image"
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-container)] py-1.5 pl-8 pr-2 text-xs text-[var(--text-primary)] focus:border-[var(--primary)] focus:outline-none"
          />
        </div>
        <span className="text-[var(--text-muted)]">
          {running} running · {containers.length} total{sudo && " · via sudo"}
        </span>
        {error && <span className="text-[var(--danger)]">{error}</span>}
        <button
          type="button"
          onClick={refreshNow}
          className="ml-auto flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-high)] px-2.5 py-1 text-[var(--text-primary)] hover:bg-[var(--surface-highest)]"
        >
          <RotateCw size={12} /> Refresh
        </button>
      </div>

      {shown.length === 0 ? (
        <p className="rounded-lg border border-[var(--border)] px-3 py-8 text-center text-xs text-[var(--text-muted)]">
          {containers.length === 0 ? "No containers on this host." : "No containers match."}
        </p>
      ) : (
        <div className="divide-y divide-[var(--border)] rounded-lg border border-[var(--border)]">
          {shown.map((c) => {
            const usage = stats[c.id];
            const isRunning = c.state === "running";
            const isPaused = c.state === "paused";
            const working = busy === c.id;
            return (
              <div key={c.id} className="flex items-center gap-3 px-3 py-2.5">
                <span
                  className="h-2 w-2 shrink-0 rounded-full"
                  style={{ backgroundColor: STATE_COLOR[c.state] ?? "var(--text-muted)" }}
                  title={c.state}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 items-baseline gap-2">
                    <span className="truncate text-sm font-medium text-[var(--text-primary)]">{c.name}</span>
                    <span className="truncate font-mono text-[11px] text-[var(--text-muted)]" title={c.image}>
                      {c.image}
                    </span>
                  </div>
                  <div className="mt-0.5 flex min-w-0 flex-wrap gap-x-3 text-[11px] text-[var(--text-muted)]">
                    <span>{c.status}</span>
                    {c.ports && (
                      <span className="truncate font-mono" title={c.ports}>
                        {c.ports}
                      </span>
                    )}
                    {usage && isRunning && (
                      <span className="font-mono">
                        CPU {usage.cpuPercent} · MEM {usage.memUsage.split(" / ")[0]} ({usage.memPercent})
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 items-center">
                  {working ? (
                    <LoaderCircle size={14} className="mx-2 animate-spin text-[var(--text-muted)]" />
                  ) : (
                    <>
                      {isRunning || isPaused ? (
                        <IconButton title="Stop" onClick={() => run(c, "stop")}>
                          <Square size={13} />
                        </IconButton>
                      ) : (
                        <IconButton title="Start" onClick={() => run(c, "start")}>
                          <Play size={13} />
                        </IconButton>
                      )}
                      <IconButton title="Restart" onClick={() => run(c, "restart")} disabled={!isRunning}>
                        <RotateCw size={13} />
                      </IconButton>
                      <IconButton
                        title={isPaused ? "Resume" : "Pause"}
                        onClick={() => run(c, isPaused ? "unpause" : "pause")}
                        disabled={!isRunning && !isPaused}
                      >
                        {isPaused ? <Play size={13} /> : <Pause size={13} />}
                      </IconButton>
                      <IconButton title="Logs" onClick={() => setLogsFor(c)}>
                        <ScrollText size={13} />
                      </IconButton>
                      <IconButton title="Open a shell in the container" onClick={() => openShell(c)} disabled={!isRunning}>
                        <SquareTerminal size={13} />
                      </IconButton>
                      <IconButton title="Remove" onClick={() => remove(c)} disabled={isRunning || isPaused} danger>
                        <Trash2 size={13} />
                      </IconButton>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
