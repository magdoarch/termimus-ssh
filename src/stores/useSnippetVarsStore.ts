import { create } from "zustand";
import { fillSnippet, snippetVariables, type SnippetVariable } from "../lib/snippetVars";

interface VariablesRequest {
  title: string;
  command: string;
  variables: SnippetVariable[];
  resolve: (filled: string | null) => void;
}

interface SnippetVarsState {
  request: VariablesRequest | null;
  /** Last value typed per variable name, offered next time (this session only) */
  lastValues: Record<string, string>;
  /** The command with its variables filled in, asking for them first; null when cancelled. */
  fill: (command: string, title?: string) => Promise<string | null>;
  finish: (values: Record<string, string> | null) => void;
}

/** Rendered by <SnippetVariablesModal /> in App.tsx. */
export const useSnippetVarsStore = create<SnippetVarsState>((set, get) => ({
  request: null,
  lastValues: {},
  fill: (command, title = "Snippet") => {
    const variables = snippetVariables(command);
    if (variables.length === 0) return Promise.resolve(command);
    // A newer run replaces a dialog that is still open.
    get().request?.resolve(null);
    return new Promise((resolve) => set({ request: { title, command, variables, resolve } }));
  },
  finish: (values) => {
    const request = get().request;
    if (!request) return;
    set((state) => ({
      request: null,
      lastValues: values ? { ...state.lastValues, ...values } : state.lastValues,
    }));
    request.resolve(values ? fillSnippet(request.command, values) : null);
  },
}));
