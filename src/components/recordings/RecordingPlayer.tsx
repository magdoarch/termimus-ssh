import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { Pause, Play, RotateCcw } from "lucide-react";
import { getTerminalTheme } from "../../lib/terminalThemes";
import { useTerminalThemeStore } from "../../stores/useTerminalThemeStore";
import { formatDuration } from "../../lib/format";

interface CastEvent {
  /** Seconds from the start, after idle compression */
  at: number;
  kind: string;
  data: string;
}

/** Pauses longer than this are shortened to it when "Skip idle" is on. */
const IDLE_CAP_SECS = 2;

function parseCast(text: string, skipIdle: boolean): { cols: number; rows: number; events: CastEvent[] } {
  const lines = text.split("\n");
  const header = JSON.parse(lines[0] || "{}");
  const events: CastEvent[] = [];
  let previous = 0;
  let at = 0;
  for (const line of lines.slice(1)) {
    if (!line.trim()) continue;
    try {
      const [time, kind, data] = JSON.parse(line) as [number, string, string];
      const gap = Math.max(0, time - previous);
      previous = time;
      at += skipIdle ? Math.min(gap, IDLE_CAP_SECS) : gap;
      events.push({ at, kind, data });
    } catch {
      // A line cut off by a crash: skip it.
    }
  }
  return { cols: header.width || 80, rows: header.height || 24, events };
}

/** Plays an asciinema v2 recording in a read-only terminal. */
export function RecordingPlayer({ text }: { text: string }) {
  const [skipIdle, setSkipIdle] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [playing, setPlaying] = useState(true);
  const [position, setPosition] = useState(0);
  const cast = useMemo(() => parseCast(text, skipIdle), [text, skipIdle]);
  const duration = cast.events.length ? cast.events[cast.events.length - 1].at : 0;

  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  // Index of the next event to write, and the playback clock.
  const nextRef = useRef(0);
  const clockRef = useRef({ wall: performance.now(), position: 0 });

  useEffect(() => {
    const { themeId, font } = useTerminalThemeStore.getState();
    const term = new Terminal({
      cols: cast.cols,
      rows: cast.rows,
      disableStdin: true,
      cursorBlink: false,
      fontFamily: font.fontFamily,
      fontSize: 12,
      scrollback: 2000,
      theme: getTerminalTheme(themeId).xterm,
    });
    term.open(containerRef.current!);
    termRef.current = term;
    return () => {
      term.dispose();
      termRef.current = null;
    };
    // A new recording (or idle mode) gets a fresh terminal.
  }, [cast]);

  /** Show the recording as it is at `target` seconds. */
  const seek = useCallback(
    (target: number) => {
      const term = termRef.current;
      if (!term) return;
      term.reset();
      term.resize(cast.cols, cast.rows);
      let output = "";
      let index = 0;
      for (; index < cast.events.length && cast.events[index].at <= target; index++) {
        const event = cast.events[index];
        if (event.kind === "o") output += event.data;
        else if (event.kind === "r") {
          term.write(output);
          output = "";
          const [cols, rows] = event.data.split("x").map(Number);
          if (cols > 0 && rows > 0) term.resize(cols, rows);
        }
      }
      term.write(output);
      nextRef.current = index;
      clockRef.current = { wall: performance.now(), position: target };
      setPosition(target);
    },
    [cast]
  );

  useEffect(() => {
    seek(0);
    setPlaying(true);
  }, [seek]);

  useEffect(() => {
    if (!playing) return;
    clockRef.current = { wall: performance.now(), position: clockRef.current.position };
    let frame = 0;
    const tick = () => {
      const term = termRef.current;
      if (!term) return;
      const now = clockRef.current.position + ((performance.now() - clockRef.current.wall) / 1000) * speed;
      let output = "";
      while (nextRef.current < cast.events.length && cast.events[nextRef.current].at <= now) {
        const event = cast.events[nextRef.current++];
        if (event.kind === "o") output += event.data;
        else if (event.kind === "r") {
          term.write(output);
          output = "";
          const [cols, rows] = event.data.split("x").map(Number);
          if (cols > 0 && rows > 0) term.resize(cols, rows);
        }
      }
      if (output) term.write(output);
      setPosition(Math.min(now, duration));
      if (nextRef.current >= cast.events.length) {
        clockRef.current = { wall: performance.now(), position: duration };
        setPlaying(false);
        return;
      }
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(frame);
      // Keep the position reached when pausing.
      clockRef.current = {
        wall: performance.now(),
        position: Math.min(
          duration,
          clockRef.current.position + ((performance.now() - clockRef.current.wall) / 1000) * speed
        ),
      };
    };
  }, [playing, speed, cast, duration]);

  return (
    <div className="flex min-h-0 flex-col gap-3">
      <div className="min-h-0 overflow-auto rounded-lg border border-[var(--border)] bg-black p-2">
        <div ref={containerRef} />
      </div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-secondary)]">
        <button
          type="button"
          onClick={() => {
            if (!playing && position >= duration) seek(0);
            setPlaying((p) => !p);
          }}
          className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--primary)] text-[var(--on-primary)] hover:bg-[var(--primary-hover)]"
          title={playing ? "Pause" : "Play"}
        >
          {playing ? <Pause size={14} /> : <Play size={14} />}
        </button>
        <button
          type="button"
          onClick={() => {
            seek(0);
            setPlaying(true);
          }}
          title="From the start"
          className="rounded p-1.5 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
        >
          <RotateCcw size={14} />
        </button>
        <input
          type="range"
          min={0}
          max={Math.max(duration, 0.1)}
          step={0.1}
          value={position}
          onChange={(e) => seek(Number(e.target.value))}
          className="min-w-[160px] flex-1 accent-[var(--primary)]"
        />
        <span className="font-mono tabular-nums">
          {formatDuration(position)} / {formatDuration(duration)}
        </span>
        <select
          value={speed}
          onChange={(e) => setSpeed(Number(e.target.value))}
          className="rounded-md border border-[var(--border)] bg-[var(--surface-container)] px-2 py-1 text-xs text-[var(--text-primary)]"
        >
          {[0.5, 1, 2, 4, 8].map((s) => (
            <option key={s} value={s}>
              {s}×
            </option>
          ))}
        </select>
        <label className="flex items-center gap-1.5 text-[var(--text-muted)]" title={`Pauses longer than ${IDLE_CAP_SECS}s are shortened`}>
          <input type="checkbox" checked={skipIdle} onChange={(e) => setSkipIdle(e.target.checked)} className="accent-[var(--primary)]" />
          Skip idle
        </label>
      </div>
    </div>
  );
}
