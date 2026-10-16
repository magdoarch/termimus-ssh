import type { ReactNode } from "react";
import { ClipboardPaste, History, Network, RefreshCw, type LucideIcon } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { useSettingsStore } from "../../stores/useSettingsStore";

function ToggleRow({
  icon: Icon,
  title,
  checked,
  onChange,
  children,
}: {
  icon: LucideIcon;
  title: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  children: ReactNode;
}) {
  return (
    <div className="p-5 flex items-start justify-between gap-6">
      <div className="space-y-1">
        <div className="flex items-center gap-2 font-semibold text-[var(--text-primary)]">
          <Icon size={16} className="text-[var(--primary)]" />
          <span>{title}</span>
        </div>
        <div className="text-[11px] text-[var(--text-muted)] leading-relaxed">{children}</div>
      </div>
      <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
        <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="sr-only peer" />
        <div className="w-10 h-5.5 bg-[var(--surface-container)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4.5 after:w-4.5 after:transition-all peer-checked:bg-[var(--primary)]"></div>
      </label>
    </div>
  );
}

/** Settings > SSH & Sessions: how connections and terminal sessions behave. */
export function SessionsTab() {
  const settings = useSettingsStore(
    useShallow((s) => ({
      shareConnections: s.shareConnections,
      setShareConnections: s.setShareConnections,
      confirmMultilinePaste: s.confirmMultilinePaste,
      setConfirmMultilinePaste: s.setConfirmMultilinePaste,
      autoReconnect: s.autoReconnect,
      setAutoReconnect: s.setAutoReconnect,
      restoreTabs: s.restoreTabs,
      setRestoreTabs: s.setRestoreTabs,
    }))
  );

  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] shadow-sm overflow-hidden">
        <div className="border-b border-[var(--border)] px-5 py-4">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">Connections</h3>
          <p className="mt-0.5 text-[11px] text-[var(--text-muted)]">How Termimus logs in to your SSH hosts.</p>
        </div>
        <div className="divide-y divide-[var(--border)] text-xs">
          <ToggleRow
            icon={Network}
            title="Share one connection per host"
            checked={settings.shareConnections}
            onChange={settings.setShareConnections}
          >
            Terminal tabs, SFTP, port forwards and jump hosts to the same host use one SSH connection, like
            OpenSSH's ControlMaster, so passwords and 2FA codes are asked once. When the server refuses another
            session on it (sshd <span className="font-mono">MaxSessions</span>), a separate connection is opened
            automatically. Turn off to log in separately every time.
          </ToggleRow>
          <ToggleRow
            icon={RefreshCw}
            title="Reconnect dropped sessions"
            checked={settings.autoReconnect}
            onChange={settings.setAutoReconnect}
          >
            When a connection drops (network change, sleep, server restart), the tab stays open with its scrollback
            and logs in again, waiting a little longer after each failed try. Typing <span className="font-mono">exit</span>{" "}
            still closes the tab.
          </ToggleRow>
          <ToggleRow
            icon={History}
            title="Reopen tabs at startup"
            checked={settings.restoreTabs}
            onChange={settings.setRestoreTabs}
          >
            Opens the SSH, remote desktop and local terminal tabs you had open when Termimus last closed, each as
            its own tab (split layouts aren't kept). Hosts asking for a password or 2FA code ask at startup.
          </ToggleRow>
        </div>
      </div>

      <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-low)] shadow-sm overflow-hidden">
        <div className="border-b border-[var(--border)] px-5 py-4">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">Terminal</h3>
          <p className="mt-0.5 text-[11px] text-[var(--text-muted)]">Safety nets while you type and paste.</p>
        </div>
        <div className="divide-y divide-[var(--border)] text-xs">
          <ToggleRow
            icon={ClipboardPaste}
            title="Confirm before pasting multiple lines"
            checked={settings.confirmMultilinePaste}
            onChange={settings.setConfirmMultilinePaste}
          >
            Shows what you are about to paste when it has line breaks and the shell would run each line right
            away. Programs that handle pastes themselves (bracketed paste: modern bash and zsh prompts, vim,
            nano) aren't interrupted.
          </ToggleRow>
        </div>
      </div>
    </div>
  );
}
