// Theme management: dark (default) / light. Persisted to localStorage,
// applied via `data-theme` attribute on <html>.

export type Theme = "dark" | "light";
const KEY = "aegis.theme";

export function getInitialTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  const stored = localStorage.getItem(KEY) as Theme | null;
  if (stored === "dark" || stored === "light") return stored;
  const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
  return prefersLight ? "light" : "dark";
}

export function applyTheme(t: Theme) {
  if (typeof document === "undefined") return;
  document.documentElement.setAttribute("data-theme", t);
  document.documentElement.style.colorScheme = t;
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
}
