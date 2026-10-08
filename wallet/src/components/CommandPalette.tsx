import { useEffect, useMemo, useRef, useState } from "react";

type Cmd = {
  id: string;
  label: string;
  cat: "nav" | "copy" | "link" | "action";
  icon: string;
  run: () => void;
};

export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands = useMemo<Cmd[]>(() => {
    const scroll = (id: string) => () => {
      document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
      setOpen(false);
    };
    const link = (url: string) => () => { window.open(url, "_blank"); setOpen(false); };
    const copy = (val: string) => () => { void navigator.clipboard?.writeText(val); setOpen(false); };
    return [
      { id: "nav-chains",   label: "Jump to Multi-chain",            cat: "nav",    icon: "→", run: scroll("chains") },
      { id: "nav-derive",   label: "Jump to Live Derivation",        cat: "nav",    icon: "→", run: scroll("chains") },
      { id: "nav-why",      label: "Jump to Threat Model",           cat: "nav",    icon: "→", run: scroll("why") },
      { id: "nav-verify",   label: "Jump to Self-Verify Checklist",  cat: "nav",    icon: "→", run: scroll("verify") },
      { id: "nav-code",     label: "Jump to Code Showcase",          cat: "nav",    icon: "→", run: scroll("code") },
      { id: "nav-spec",     label: "Jump to Technical Spec",         cat: "nav",    icon: "→", run: scroll("spec") },
      { id: "link-github",  label: "Open GitHub repo",               cat: "link",   icon: "↗", run: link("https://github.com/imadegoodstuff/aegis-protocol") },
      { id: "link-spec",    label: "Open SPEC.md",                   cat: "link",   icon: "↗", run: link("https://github.com/imadegoodstuff/aegis-protocol/blob/main/SPEC.md") },
      { id: "link-adapt",   label: "Open ADAPTERS.md",               cat: "link",   icon: "↗", run: link("https://github.com/imadegoodstuff/aegis-protocol/blob/main/ADAPTERS.md") },
      { id: "link-verify",  label: "Open user-verification docs",    cat: "link",   icon: "↗", run: link("https://github.com/imadegoodstuff/aegis-protocol/blob/main/docs/USER_VERIFICATION.md") },
      { id: "link-test",    label: "Open testnet demo guide",        cat: "link",   icon: "↗", run: link("https://github.com/imadegoodstuff/aegis-protocol/blob/main/docs/TESTNET_DEMO.md") },
      { id: "copy-repo",    label: "Copy git clone URL",             cat: "copy",   icon: "⌘", run: copy("git clone https://github.com/imadegoodstuff/aegis-protocol") },
      { id: "copy-npm",     label: "Copy wallet install snippet",    cat: "copy",   icon: "⌘", run: copy("cd wallet && npm install && npm run dev") },
      { id: "copy-forge",   label: "Copy forge build + test snippet",cat: "copy",   icon: "⌘", run: copy("cd evm && forge build && forge test") },
      { id: "act-top",      label: "Scroll to top",                  cat: "action", icon: "↑", run: () => { window.scrollTo({ top: 0, behavior: "smooth" }); setOpen(false); } },
    ];
  }, []);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return commands;
    return commands.filter((c) => c.label.toLowerCase().includes(s) || c.cat.includes(s));
  }, [commands, q]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((v) => !v); }
      else if (e.key === "Escape" && open) { e.preventDefault(); setOpen(false); }
      else if (open && e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(filtered.length - 1, i + 1)); }
      else if (open && e.key === "ArrowUp")   { e.preventDefault(); setActive((i) => Math.max(0, i - 1)); }
      else if (open && e.key === "Enter")     { e.preventDefault(); filtered[active]?.run(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, filtered, active]);

  useEffect(() => {
    if (open) { setQ(""); setActive(0); setTimeout(() => inputRef.current?.focus(), 20); }
  }, [open]);
  useEffect(() => { setActive(0); }, [q]);

  if (!open) return null;
  return (
    <div className="cp-backdrop" onClick={() => setOpen(false)}>
      <div className="cp" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cp-input"
          placeholder="Type a command or search…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <div className="cp-list">
          {filtered.length === 0 && (
            <div className="cp-item" style={{ color: "var(--text-4)" }}>
              <span className="label">No matches</span>
            </div>
          )}
          {filtered.map((c, i) => (
            <div
              key={c.id}
              className={"cp-item" + (i === active ? " active" : "")}
              onMouseEnter={() => setActive(i)}
              onClick={() => c.run()}
            >
              <span className="label">
                <span className="icon">{c.icon}</span>
                <span>{c.label}</span>
              </span>
              <span className="cat">{c.cat}</span>
            </div>
          ))}
        </div>
        <div className="cp-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate · <kbd>↵</kbd> select · <kbd>esc</kbd> close</span>
          <span>⌘K / Ctrl+K anywhere</span>
        </div>
      </div>
    </div>
  );
}
