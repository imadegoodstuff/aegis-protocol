import { CHAINS } from "../data/chains";

export default function ChainDashboard() {
  return (
    <div className="card chain-dash">
      <div className="chain-dash-head">
        <div>
          <div className="chain-dash-title">Deployment matrix</div>
          <div className="chain-dash-sub">one BIP-39 seed · 13 live surfaces</div>
        </div>
        <div className="chain-dash-addr">
          <span className="k">EVM</span>
          <span className="v">0xAEG5…b2E1</span>
          <span className="chip chip-accent">same addr · all EVM</span>
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
                c.status === "live" ? "ok" : c.status === "testnet" ? "soon" : ""
              }`}
            >
              {c.status === "live"
                ? c.sameAddr ? "LIVE · SAME ADDR" : "LIVE"
                : c.status === "testnet" ? "TESTNET-READY" : "RESEARCH"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
