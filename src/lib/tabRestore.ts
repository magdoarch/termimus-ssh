import type { SshTab } from "../stores/useSessionStore";

const STORAGE_KEY = "termimus_open_tabs";

/** A tab as remembered for the next start (Settings > SSH & Sessions). */
export interface SavedTab {
  hostId?: string;
  local?: boolean;
  command?: string;
  label?: string;
}

export function saveOpenTabs(tabs: SshTab[]) {
  const saved: SavedTab[] = tabs.map((tab) =>
    tab.isLocal ? { local: true } : { hostId: tab.hostId, command: tab.command, label: tab.command ? tab.hostLabel : undefined }
  );
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(saved));
  } catch {
    // Private mode or full storage: nothing to restore next time.
  }
}

export function loadSavedTabs(): SavedTab[] {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]");
    return Array.isArray(saved) ? saved : [];
  } catch {
    return [];
  }
}
