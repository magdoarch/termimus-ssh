import { create } from "zustand";

export type HostPanelTab = "overview" | "docker";

interface HostPanelState {
  hostId: string | null;
  tab: HostPanelTab;
  open: (hostId: string, tab?: HostPanelTab) => void;
  setTab: (tab: HostPanelTab) => void;
  close: () => void;
}

/** The server dashboard of one SSH host, rendered by <HostPanel /> in App.tsx. */
export const useHostPanelStore = create<HostPanelState>((set) => ({
  hostId: null,
  tab: "overview",
  open: (hostId, tab = "overview") => set({ hostId, tab }),
  setTab: (tab) => set({ tab }),
  close: () => set({ hostId: null }),
}));
