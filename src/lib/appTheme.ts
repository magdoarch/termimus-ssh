import { getCurrentWindow } from "@tauri-apps/api/window";

/** UI color theme. The terminal has its own theme (Settings → Terminal). */
export type AppTheme = "dark" | "light" | "system";

const systemPrefersLight = () => window.matchMedia("(prefers-color-scheme: light)").matches;

export function resolveAppTheme(theme: AppTheme): "dark" | "light" {
  if (theme === "system") return systemPrefersLight() ? "light" : "dark";
  return theme;
}

let systemListener: ((e: MediaQueryListEvent) => void) | null = null;

/**
 * Apply the theme to <html data-theme> (which switches the CSS variables in
 * index.css) and to the native window, so OS-drawn bits and
 * prefers-color-scheme match. "system" follows OS changes live.
 */
export function applyAppTheme(theme: AppTheme) {
  const media = window.matchMedia("(prefers-color-scheme: light)");
  if (systemListener) {
    media.removeEventListener("change", systemListener);
    systemListener = null;
  }

  const setResolved = () => {
    document.documentElement.dataset.theme = resolveAppTheme(theme);
  };
  setResolved();

  if (theme === "system") {
    systemListener = setResolved;
    media.addEventListener("change", systemListener);
  }

  // null = follow the OS; the window starts forced to Dark (tauri.conf.json).
  // The webview's prefers-color-scheme updates asynchronously, so resolve again
  // once the window theme has been applied.
  getCurrentWindow()
    .setTheme(theme === "system" ? null : theme)
    .then(setResolved)
    .catch(() => {});
}
