import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { AppTheme } from "../lib/appTheme";

export type AutoLockPolicy =
  | "never"
  | "on_close"
  | "15min"
  | "1hour"
  | "on_focus_loss";

export const AUTO_LOCK_LABELS: Record<AutoLockPolicy, string> = {
  never: "Never (manual lock only)",
  on_close: "When app closes",
  "15min": "After 15 minutes idle",
  "1hour": "After 1 hour idle",
  on_focus_loss: "When app loses focus",
};

interface SettingsState {
  useOsKeyring: boolean;
  useBiometrics: boolean;
  autoLockPolicy: AutoLockPolicy;
  /** UI theme; read by public/theme-init.js before the bundle loads */
  appTheme: AppTheme;
  /** One SSH connection per host, shared by tabs, SFTP and tunnels (backend pool) */
  shareConnections: boolean;
  /** Ask before pasting text that would run line by line in the shell */
  confirmMultilinePaste: boolean;
  /** Reconnect SSH tabs whose connection dropped (not after `exit`) */
  autoReconnect: boolean;
  /** Reopen the previous session's tabs at startup */
  restoreTabs: boolean;
  setAppTheme: (v: AppTheme) => void;
  setShareConnections: (v: boolean) => void;
  setConfirmMultilinePaste: (v: boolean) => void;
  setAutoReconnect: (v: boolean) => void;
  setRestoreTabs: (v: boolean) => void;
  setUseOsKeyring: (v: boolean) => void;
  setUseBiometrics: (v: boolean) => void;
  setAutoLockPolicy: (v: AutoLockPolicy) => void;
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      useOsKeyring: false,
      useBiometrics: false,
      autoLockPolicy: "on_close",
      appTheme: "dark",
      shareConnections: true,
      confirmMultilinePaste: true,
      autoReconnect: true,
      restoreTabs: false,
      setAppTheme: (v) => set({ appTheme: v }),
      setShareConnections: (v) => set({ shareConnections: v }),
      setConfirmMultilinePaste: (v) => set({ confirmMultilinePaste: v }),
      setAutoReconnect: (v) => set({ autoReconnect: v }),
      setRestoreTabs: (v) => set({ restoreTabs: v }),
      setUseOsKeyring: (v) => set({ useOsKeyring: v }),
      setUseBiometrics: (v) => set({ useBiometrics: v }),
      setAutoLockPolicy: (v) => set({ autoLockPolicy: v }),
    }),
    {
      name: "termimus_settings",
    }
  )
);
