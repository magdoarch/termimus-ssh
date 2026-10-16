import { create } from "zustand";

interface InstallKeyTarget {
  /** Preselected host (from the host menu) */
  hostId?: string;
  /** Preselected Keychain key (from the Keychain) */
  credentialId?: string;
}

interface InstallKeyState {
  target: InstallKeyTarget | null;
  open: (target: InstallKeyTarget) => void;
  close: () => void;
}

/** "Install SSH key on a host" dialog, rendered by <InstallKeyModal /> in App.tsx. */
export const useInstallKeyStore = create<InstallKeyState>((set) => ({
  target: null,
  open: (target) => set({ target }),
  close: () => set({ target: null }),
}));
