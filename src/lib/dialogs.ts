import { useAuthPromptStore } from "../stores/useAuthPromptStore";
import { useConfirmStore } from "../stores/useConfirmStore";

/**
 * A confirmation or login prompt is open above the other dialogs, so Escape
 * belongs to it. Panels check this before closing themselves on Escape.
 */
export function dialogOnTop(): boolean {
  return useConfirmStore.getState().isOpen || useAuthPromptStore.getState().queue.length > 0;
}
