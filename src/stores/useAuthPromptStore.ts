import { create } from "zustand";
import { listen } from "@tauri-apps/api/event";
import { api, AuthPromptEvent } from "../lib/api";

interface AuthPromptState {
  /** Prompts waiting for an answer, oldest first (several logins can ask at once) */
  queue: AuthPromptEvent[];
  /** Start receiving prompts from the backend. Idempotent. */
  listenForPrompts: () => void;
  respond: (requestId: string, answers: string[] | null) => Promise<void>;
}

let listening = false;

export const useAuthPromptStore = create<AuthPromptState>((set) => ({
  queue: [],

  listenForPrompts: () => {
    if (listening) return;
    listening = true;
    listen<AuthPromptEvent>("ssh-auth-prompt", ({ payload }) => {
      set((s) => ({ queue: [...s.queue, payload] }));
    });
    // The backend withdrew the prompt (it timed out).
    listen<string>("ssh-auth-prompt-closed", ({ payload }) => {
      set((s) => ({ queue: s.queue.filter((r) => r.requestId !== payload) }));
    });
  },

  respond: async (requestId, answers) => {
    set((s) => ({ queue: s.queue.filter((r) => r.requestId !== requestId) }));
    try {
      await api.respondAuthPrompt(requestId, answers);
    } catch (e) {
      // Already expired: the login has failed on its own.
      console.warn("Login prompt response failed:", e);
    }
  },
}));
