import { useEffect, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import { Cpu, HardDrive, LoaderCircle, MemoryStick, Network, RotateCw, Server } from "lucide-react";
import { api, type HostStats, type HostStatsEvent } from "../../lib/api";
import { formatBytes, formatDuration, formatRate } from "../../lib/format";

const HISTORY = 60;

function usageColor(percent: number): string {
  if (percent >= 90) return "var(--danger)";
  if (percent >= 75) return "var(--warning)";
  return "var(--primary)";
}

function Bar({ percent }: { percent: number }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--surface-high)]">
      <div
        className="h-full rounded-full transition-[width] duration-500"
        style={{ width: `${Math.min(100, Math.max(0, percent))}%`, backgroundColor: usageColor(percent) }}
      />
    </div>
  );
}

/** A 0–100 history as a filled line. */
function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <div className="h-12" />;
  const step = 100 / (HISTORY - 1);
  const offset = (HISTORY - values.length) * step;
  const points = values.map((v, i) => `${(offset + i * step).toFixed(2)},${(40 - (v / 100) * 38).toFixed(2)}`);
  return (
    <svg viewBox="0 0 100 40" preserveAspectRatio="none" className="h-12 w-full">
      <polygon points={`${offset.toFixed(2)},40 ${points.join(" ")} 100,40`} fill="var(--primary)" opacity="0.15" />
      <polyline points={points.join(" ")} fill="none" stroke="var(--primary)" strokeWidth="1.2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

function Card({ icon: Icon, title, aside, children }: { icon: typeof Cpu; title: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-container)]/50 p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-xs font-semibold text-[var(--text-secondary)]">
          <Icon size={14} className="text-[var(--primary)]" />
          {title}
        </span>
        {aside && <span className="font-mono text-[11px] text-[var(--text-muted)]">{aside}</span>}
      </div>
      {children}
    </div>
  );
}

/** Live CPU, memory, disk and network figures of an SSH host. */
export function HostStatsView({ hostId }: { hostId: string }) {
  const [stats, setStats] = useState<HostStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cpuHistory, setCpuHistory] = useState<number[]>([]);
  const [attempt, setAttempt] = useState(0);
  const monitorId = useRef(`monitor-${hostId}-${Math.random().toString(36).slice(2, 8)}`).current;

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    setError(null);
    (async () => {
      unlisten = await listen<HostStatsEvent>(`host-stats-${monitorId}`, (event) => {
        if (cancelled) return;
        const { stats: next, error: failed } = event.payload;
        if (next) {
          setStats(next);
          setError(null);
          if (next.cpuPercent !== null) {
            setCpuHistory((h) => [...h, next.cpuPercent as number].slice(-HISTORY));
          }
        } else if (failed) {
          setError(failed);
        }
      });
      if (cancelled) {
        unlisten();
        return;
      }
      try {
        await api.startHostMonitor(hostId, monitorId);
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    })();
    return () => {
      cancelled = true;
      unlisten?.();
      api.stopHostMonitor(monitorId).catch(() => {});
    };
  }, [hostId, monitorId, attempt]);

  if (!stats) {
    return (
      <div className="flex min-h-[240px] flex-col items-center justify-center gap-3 text-xs text-[var(--text-muted)]">
        {error ? (
          <>
            <p className="max-w-md text-center text-[var(--danger)]">{error}</p>
            <button
              type="button"
              onClick={() => setAttempt((a) => a + 1)}
              className="flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface-high)] px-3 py-1.5 text-[var(--text-primary)] hover:bg-[var(--surface-highest)]"
            >
              <RotateCw size={12} /> Try again
            </button>
          </>
        ) : (
          <span className="flex items-center gap-2">
            <LoaderCircle size={14} className="animate-spin" /> Reading server stats…
          </span>
        )}
      </div>
    );
  }

  const memPercent = stats.memTotalBytes ? (stats.memUsedBytes / stats.memTotalBytes) * 100 : 0;
  const swapPercent = stats.swapTotalBytes ? (stats.swapUsedBytes / stats.swapTotalBytes) * 100 : 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[11px] text-[var(--text-muted)]">
        <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
          <Server size={12} /> {stats.os || "Linux"}
        </span>
        <span className="font-mono">{stats.kernel}</span>
        <span className="font-mono">{stats.hostname}</span>
        <span>up {formatDuration(stats.uptimeSecs)}</span>
        {error && <span className="text-[var(--warning)]">{error}</span>}
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card
          icon={Cpu}
          title="CPU"
          aside={`load ${stats.load.map((l) => l.toFixed(2)).join(" ")} · ${stats.cpuCount} cores`}
        >
          <div className="mb-1 flex items-baseline gap-1">
            <span className="text-2xl font-semibold text-[var(--text-primary)]">
              {stats.cpuPercent === null ? "…" : stats.cpuPercent.toFixed(0)}
            </span>
            <span className="text-xs text-[var(--text-muted)]">%</span>
          </div>
          <Sparkline values={cpuHistory} />
        </Card>

        <Card icon={MemoryStick} title="Memory" aside={`${memPercent.toFixed(0)}%`}>
          <p className="mb-2 font-mono text-[11px] text-[var(--text-secondary)]">
            {formatBytes(stats.memUsedBytes)} of {formatBytes(stats.memTotalBytes)}
          </p>
          <Bar percent={memPercent} />
          {stats.swapTotalBytes > 0 && (
            <>
              <p className="mb-2 mt-3 font-mono text-[11px] text-[var(--text-muted)]">
                Swap {formatBytes(stats.swapUsedBytes)} of {formatBytes(stats.swapTotalBytes)}
              </p>
              <Bar percent={swapPercent} />
            </>
          )}
        </Card>

        <Card icon={Network} title="Network" aside="all interfaces">
          <div className="grid grid-cols-2 gap-3 font-mono text-[var(--text-primary)]">
            <div>
              <p className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">↓ in</p>
              <p className="text-sm">{stats.netRxRate === null ? "…" : formatRate(stats.netRxRate)}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">↑ out</p>
              <p className="text-sm">{stats.netTxRate === null ? "…" : formatRate(stats.netTxRate)}</p>
            </div>
          </div>
        </Card>

        <Card icon={HardDrive} title="Disks">
          <div className="space-y-2.5">
            {stats.disks.map((disk) => {
              const percent = disk.totalBytes ? (disk.usedBytes / disk.totalBytes) * 100 : 0;
              return (
                <div key={disk.filesystem}>
                  <div className="mb-1 flex items-center justify-between gap-2 font-mono text-[11px]">
                    <span className="truncate text-[var(--text-secondary)]" title={disk.filesystem}>
                      {disk.mount}
                    </span>
                    <span className="shrink-0 text-[var(--text-muted)]">
                      {formatBytes(disk.usedBytes)} / {formatBytes(disk.totalBytes)}
                    </span>
                  </div>
                  <Bar percent={percent} />
                </div>
              );
            })}
            {stats.disks.length === 0 && <p className="text-[11px] text-[var(--text-muted)]">No disks reported.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
}
