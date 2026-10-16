import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { LoaderCircle, Pause, Play, RotateCcw } from "lucide-react";
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
/** Output written per step when jumping to a point (keeps xterm's queue small). */
const SEEK_CHUNK = 256 * 1024;

function parseCast(text: string, skipIdle: boolean): { cols: number; rows: number; events: CastEvent[] } {
  const lines = text.split("\n");
  let header: { width?: number; height?: number } = {};
  try {
    header = JSON.parse(lines[0] || "{}");
  } catch {
    // Not a cast header: play what follows anyway.
  }
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

function parseSize(data: string): [number, number] | null {
  const [cols, rows] = data.split("x").map(Number);
  return cols > 0 && rows > 0 ? [cols, rows] : null;
}

/** Plays an asciinema v2 recording in a read-only terminal. */
export function RecordingPlayer({ text }: { text: string }) {
  const [skipIdle, setSkipIdle] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [playing, setPlaying] = useState(false);
  const [seeking, setSeeking] = useState(false);
  const [position, setPosition] = useState(0);
  const cast = useMemo(() => parseCast(text, skipIdle), [text, skipIdle]);
  const duration = cast.events.length ? cast.events[cast.events.length - 1].at : 0;

  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  // Index of the next event to write, and the playback clock.
  const nextRef = useRef(0);
  const clockRef = useRef({ wall: performance.now(), position: 0 });
  // Bumped by every seek: a render for an older one stops.
  const generation = useRef(0);

  useEffect(
    () => () => {
      generation.current++;
      termRef.current?.dispose();
      termRef.current = null;
    },
    []
  );

  /**
   * Show the recording as it is at `target` seconds, on a fresh terminal (so
   * nothing still queued for the old one shows up), then play on if asked.
   */
  const seek = useCallback(
    async (target: number, resume: boolean) => {
      const gen = ++generation.current;
      setPlaying(false);
      setSeeking(true);
      termRef.current?.dispose();
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

      // Writes are queued inside xterm: wait for each before resizing or
      // writing more, so sizes change in order and the queue stays small.
      const write = (data: string) => new Promise<void>((resolve) => term.write(data, resolve));
      let chunk = "";
      let index = 0;
      for (; index < cast.events.length && cast.events[index].at <= target; index++) {
        if (gen !== generation.current) return;
        const event = cast.events[index];
        if (event.kind === "o") {
          chunk += event.data;
          if (chunk.length >= SEEK_CHUNK) {
            await write(chunk);
            chunk = "";
          }
        } else if (event.kind === "r") {
          if (chunk) await write(chunk);
          chunk = "";
          const size = parseSize(event.data);
          if (size) term.resize(...size);
        }
      }
      if (chunk) await write(chunk);
      if (gen !== generation.current) return;
      nextRef.current = index;
      clockRef.current = { wall: performance.now(), position: target };
      setPosition(target);
      setSeeking(false);
      setPlaying(resume);
    },
    [cast]
  );

  // A new recording (or idle mode) starts over.
  useEffect(() => {
    seek(0, true);
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
        if (event.kind === "o") {
          output += event.data;
        } else if (event.kind === "r") {
          const size = parseSize(event.data);
          // Resize once the output before it is drawn.
          term.write(output, () => size && term.resize(...size));
          output = "";
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
      <div className="relative min-h-0 overflow-auto rounded-lg border border-[var(--border)] bg-black p-2">
        <div ref={containerRef} />
        {seeking && (
          <LoaderCircle size={16} className="absolute right-3 top-3 animate-spin text-[var(--text-muted)]" />
        )}
      </div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-secondary)]">
        <button
          type="button"
          onClick={() => {
            if (playing) setPlaying(false);
            else if (position >= duration) seek(0, true);
            else setPlaying(true);
          }}
          disabled={seeking}
          className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--primary)] text-[var(--on-primary)] hover:bg-[var(--primary-hover)] disabled:opacity-50"
          title={playing ? "Pause" : "Play"}
        >
          {playing ? <Pause size={14} /> : <Play size={14} />}
        </button>
        <button
          type="button"
          onClick={() => seek(0, true)}
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
          onChange={(e) => seek(Number(e.target.value), playing)}
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
