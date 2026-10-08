import { CHAINS, type PqStatus } from "../data/chains";

const PQ_LABEL: Record<PqStatus, { text: string; cls: string }> = {
  contract: { text: "verifier ready · factory not published", cls: "soon" },
  source:   { text: "verifier source · not deployed",         cls: "" },
  blocked:  { text: "needs OP_CAT",                           cls: "" },
  none:     { text: "—",                                      cls: "" },
};

export default function ChainDashboard() {
  const evm = CHAINS.filter((c) => c.family === "EVM").length;
  return (
    <div className="card chain-dash">
      <div className="chain-dash-head">
        <div>
          <div className="chain-dash-title">Table 2 · chain matrix</div>
          <div className="chain-dash-sub">
            address = standard derivation, importable today · pq = state of the CCHS verifier on that chain
          </div>
        </div>
        <div className="chain-dash-legend">
          <span><i className="chain-dot" /> address live</span>
          <span><i className="chain-dot pending" /> preview</span>
          <span className="chip chip-accent">{evm} EVM chains · one address</span>
        </div>
      </div>

      <div className="chain-grid">
        {CHAINS.map((c) => {
          const pq = PQ_LABEL[c.pq];
          return (
            <div key={c.name} className="chain-cell" title={c.wallet ? `Import to ${c.wallet}` : undefined}>
              <div className="chain-name">
                <span className={`chain-dot ${c.status !== "mainnet" ? "pending" : ""}`} />
                <span className="chain-label">{c.name}</span>
                <span className="chain-set mono">{c.set}</span>
              </div>
              <span className={`chain-status ${pq.cls}`}>{pq.text}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
