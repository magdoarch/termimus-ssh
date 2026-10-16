import { create } from "zustand";

export interface ReconnectStatus {
  hostId: string;
  /** 1-based number of the attempt being waited for */
  attempt: number;
  maxAttempts: number;
  /** Epoch ms when it starts */
  at: number;
  /** Why the previous attempt failed */
  error: string | null;
}

interface ReconnectState {
  /** SSH tabs whose connection dropped and that are waiting to reconnect */
  pending: Record<string, ReconnectStatus>;
  set: (sessionId: string, status: ReconnectStatus) => void;
  clear: (sessionId: string) => void;
}

/** UI state of automatic reconnects; the timers live in XtermView. */
export const useReconnectStore = create<ReconnectState>((set) => ({
  pending: {},
  set: (sessionId, status) => set((s) => ({ pending: { ...s.pending, [sessionId]: status } })),
  clear: (sessionId) =>
    set((s) => {
      if (!(sessionId in s.pending)) return s;
      const pending = { ...s.pending };
      delete pending[sessionId];
      return { pending };
    }),
}));
