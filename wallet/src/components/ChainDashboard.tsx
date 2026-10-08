import { CHAINS } from "../data/chains";

export default function ChainDashboard() {
  return (
    <div className="glass chain-dash">
      <div className="chain-dash-head">
        <div>
          <div className="section-eyebrow" style={{ marginBottom: 6 }}>Live preview</div>
          <div style={{ fontSize: 18, fontWeight: 600 }}>Your Aegis account, every chain</div>
        </div>
        <div className="chain-dash-addr">
          <span className="label">EVM addr</span>
          <span className="val mono">0xAEG5…b2E1</span>
          <span className="chip">same on all EVM chains</span>
        </div>
      </div>

      <div className="chain-grid">
        {CHAINS.map((c) => (
          <div key={c.name} className="chain-cell">
            <div className="chain-name">
              <span className={`chain-dot ${c.status !== "live" ? "pending" : ""}`} />
              <span className="chain-label">{c.name}</span>
            </div>
            <span
              className={`chain-status ${
                c.status === "live" ? "ok" : c.status === "soon" ? "soon" : ""
              }`}
            >
              {c.status === "live"
                ? c.sameAddr
                  ? "deployed · same addr"
                  : "deployed"
                : c.status === "soon"
                ? "roadmap"
                : "research"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
