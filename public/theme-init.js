// Runs before the app bundle so a light theme doesn't flash dark on startup.
// Mirrors resolveAppTheme() in src/lib/appTheme.ts; reads the persisted
// useSettingsStore state. External file (not inline) to satisfy the CSP.
(function () {
  try {
    var raw = localStorage.getItem("termimus_settings");
    var theme = raw ? (JSON.parse(raw).state || {}).appTheme : null;
    var light =
      theme === "light" ||
      (theme === "system" && window.matchMedia("(prefers-color-scheme: light)").matches);
    if (light) document.documentElement.dataset.theme = "light";
  } catch (e) {
    // Storage unavailable: keep the dark default
  }
})();
