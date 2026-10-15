import { create } from "zustand";
import { listen } from "@tauri-apps/api/event";
import { api, PortForwardRule, PortForwardInput, TunnelStatusEvent } from "../lib/api";

let statusListener: Promise<() => void> | null = null;

interface TunnelState {
  rules: PortForwardRule[];
  activeRuleIds: Set<string>;
  /** Why a tunnel stopped on its own (cleared when it is started again) */
  ruleErrors: Record<string, string>;
  isLoading: boolean;
  error: string | null;
  isModalOpen: boolean;
  editingRule: PortForwardRule | null;
  startingRuleId: string | null;

  refresh: () => Promise<void>;
  /** Track tunnels starting/stopping in the backend (e.g. SSH connection lost). Idempotent. */
  listenForStatus: () => void;
  saveRule: (input: PortForwardInput, ruleId?: string) => Promise<void>;
  deleteRule: (id: string) => Promise<void>;
  toggleTunnel: (rule: PortForwardRule) => Promise<void>;
  openCreateModal: () => void;
  openEditModal: (rule: PortForwardRule) => void;
  closeModal: () => void;
}

export const useTunnelStore = create<TunnelState>((set, get) => ({
  rules: [],
  activeRuleIds: new Set(),
  ruleErrors: {},
  isLoading: false,
  error: null,
  isModalOpen: false,
  editingRule: null,
  startingRuleId: null,

  refresh: async () => {
    if (get().rules.length === 0) {
      set({ isLoading: true, error: null });
    }
    try {
      const [rules, active] = await Promise.all([
        api.listTunnelRules(),
        api.listActiveTunnels(),
      ]);
      set({ rules, activeRuleIds: new Set(active), isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
    }
  },

  listenForStatus: () => {
    if (statusListener) return;
    statusListener = listen<TunnelStatusEvent>("tunnel-status", ({ payload }) => {
      set((state) => {
        const activeRuleIds = new Set(state.activeRuleIds);
        const ruleErrors = { ...state.ruleErrors };
        if (payload.state === "started") {
          activeRuleIds.add(payload.ruleId);
          delete ruleErrors[payload.ruleId];
        } else {
          activeRuleIds.delete(payload.ruleId);
          if (payload.error) ruleErrors[payload.ruleId] = payload.error;
        }
        return { activeRuleIds, ruleErrors };
      });
    });
  },

  saveRule: async (input, ruleId) => {
    await api.saveTunnelRule(input, ruleId);
    await get().refresh();
  },

  deleteRule: async (id: string) => {
    const { activeRuleIds } = get();
    if (activeRuleIds.has(id)) {
      await api.stopTunnel(id).catch(() => {});
    }
    await api.deleteTunnelRule(id);
    await get().refresh();
  },

  toggleTunnel: async (rule: PortForwardRule) => {
    const { activeRuleIds } = get();
    const isActive = activeRuleIds.has(rule.id);
    set((state) => {
      const ruleErrors = { ...state.ruleErrors };
      delete ruleErrors[rule.id];
      return { startingRuleId: rule.id, error: null, ruleErrors };
    });

    try {
      if (isActive) {
        await api.stopTunnel(rule.id);
      } else {
        await api.startTunnel(rule.id);
      }
      await get().refresh();
    } catch (e) {
      set({ error: `Tunnel error: ${String(e)}` });
    } finally {
      set({ startingRuleId: null });
    }
  },

  openCreateModal: () => set({ isModalOpen: true, editingRule: null }),
  openEditModal: (rule) => set({ isModalOpen: true, editingRule: rule }),
  closeModal: () => set({ isModalOpen: false, editingRule: null }),
}));
