import { create } from "zustand";

interface RecordingState {
  /** Running recordings: session id -> file name */
  active: Record<string, string>;
  setActive: (sessionId: string, name: string | null) => void;
  /** The recordings list / player dialog */
  isOpen: boolean;
  open: () => void;
  close: () => void;
}

export const useRecordingStore = create<RecordingState>((set) => ({
  active: {},
  setActive: (sessionId, name) =>
    set((s) => {
      const active = { ...s.active };
      if (name) active[sessionId] = name;
      else delete active[sessionId];
      return { active };
    }),
  isOpen: false,
  open: () => set({ isOpen: true }),
  close: () => set({ isOpen: false }),
}));
