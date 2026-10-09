// Table 1 — parameter sets and measured costs. Values come from CCHS.spec.md
// §5.2 and §9 (deployed build: solc 0.8.37, optimizer 1e6 runs, viaIR, Cancun).

const ROWS: Array<{ k: string; s: string; kk: string; unit?: string }> = [
  { k: "Hash function",               s: "SHA-256",            kk: "keccak256" },
  { k: "Winternitz w / chains",       s: "16 / 67",            kk: "16 / 67" },
  { k: "Layers × height",             s: "2 × 10",             kk: "2 × 10" },
  { k: "Signatures per key",          s: "1 048 576",          kk: "1 048 576" },
  { k: "Recoveries per key",          s: "256",                kk: "256" },
  { k: "Signature, cached subtree",   s: "2 464",              kk: "2 464", unit: "B" },
  { k: "Signature, first in subtree", s: "4 928",              kk: "4 928", unit: "B" },
  { k: "Execution gas, cached",       s: "≈ 209 000",          kk: "≈ 116 000" },
  { k: "Execution gas, first",        s: "≈ 452 000",          kk: "≈ 249 000" },
  { k: "Execution gas, recovery",     s: "≈ 201 000",          kk: "≈ 107 000" },
  { k: "Runtime code",                s: "6 184",              kk: "6 072", unit: "B" },
  { k: "External verifier contract",  s: "none",               kk: "none" },
  { k: "Client state",                s: "one integer per chain and epoch", kk: "one integer per chain and epoch" },
  { k: "Primary use",                 s: "non-EVM chains (Solana: C-20)", kk: "EVM default" },
];

export default function ParamsTable() {
  return (
    <figure className="fig table-fig">
      <div className="table-scroll">
        <table className="ptable">
          <thead>
            <tr>
              <th scope="col">Parameter</th>
              <th scope="col">CCHS-S-20</th>
              <th scope="col">CCHS-K-20</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.k}>
                <th scope="row">{r.k}</th>
                <td className="mono num">{r.s}{r.unit ? <span className="unit"> {r.unit}</span> : null}</td>
                <td className="mono num">{r.kk}{r.unit ? <span className="unit"> {r.unit}</span> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <figcaption>
        <span className="fig-num">Table 1</span>
        <span className="fig-text">
          Both sets share one account contract and one master key; the client keeps only the highest leaf it has signed,
          per chain and epoch (the index itself lives on chain). Gas is execution only (excludes 21 K intrinsic and
          calldata), measured in an EVM with client-produced signatures. For reference, on-chain SPHINCS+ C13 verification
          costs ≈ 190 K gas per signature plus a separate 14.6 KB verifier contract.
        </span>
      </figcaption>
    </figure>
  );
}
