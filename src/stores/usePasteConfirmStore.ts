import { create } from "zustand";

interface PasteRequest {
  /** Normalized to \n line endings */
  text: string;
  paste: (text: string) => void;
  /** Called when the dialog closes either way (to refocus the terminal) */
  done: () => void;
}

interface PasteConfirmState {
  request: PasteRequest | null;
  ask: (request: PasteRequest) => void;
  close: () => void;
}

/** Pending "paste these lines?" question, rendered by <PasteConfirmModal /> in App.tsx. */
export const usePasteConfirmStore = create<PasteConfirmState>((set) => ({
  request: null,
  ask: (request) => set({ request }),
  close: () => set({ request: null }),
}));
