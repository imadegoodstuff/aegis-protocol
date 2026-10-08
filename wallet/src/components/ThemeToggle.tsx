import { useEffect, useState } from "react";
import { applyTheme, getInitialTheme, type Theme } from "../theme";

export default function ThemeToggle() {
  const [t, setT] = useState<Theme>(getInitialTheme);
  useEffect(() => applyTheme(t), [t]);
  return (
    <button
      className="theme-toggle"
      aria-label={`Switch to ${t === "dark" ? "light" : "dark"} theme`}
      title="Toggle theme"
      onClick={() => setT((v) => (v === "dark" ? "light" : "dark"))}
    >
      <span className="ic-bg moon" aria-hidden>☾</span>
      <span className="ic-bg sun"  aria-hidden>☀</span>
      <span className="knob">{t === "dark" ? "☾" : "☀"}</span>
    </button>
  );
}
