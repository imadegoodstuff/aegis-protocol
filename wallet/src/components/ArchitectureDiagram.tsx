import { useEffect, useState } from "react";

type AdapterId = "evm" | "tron" | "svm" | "cosmos" | "near" | "aptos" | "sui" | "cairo" | "ton" | "bitcoin";

/** pq = CCHS verifier state. "contract" = complete + tested, factory not published; "source" = code against vectors; "blocked" = external dependency. */
type Pq = "contract" | "source" | "blocked";

type Adapter = {
  id: AdapterId; name: string; family: string; set: string;
  addrStatus: "mainnet" | "preview";
  pq: Pq;
  address: string; hash: string; storage: string; path: string; blurb: string;
};

const ADAPTERS: Adapter[] = [
  { id: "evm", name: "EVM × 12", family: "Solidity 0.8.37", set: "CCHS-K-20",
    addrStatus: "mainnet", pq: "contract",
    address: "CREATE2(factory, keccak(root ‖ recRoot ‖ set), initCode)",
    hash: "keccak256 opcode (S-20: precompile 0x02)", storage: "mapping((epoch<<64)|treeIdx → bytes32)", path: "evm/src/AegisCCHSBase.sol",
    blurb: "AegisCCHSBase holds all logic; AegisCCHS and AegisCCHSK bind the hash. The signer chooses the leaf index (monotonic, bound into the digest): execute for a cached subtree, executeFirst to register one. 20 Foundry tests per set plus factory tests driven by client-generated vectors, interop verified in an EVM. The factory lives at 0xAa61…0611 on every chain; it is published nowhere yet, and the first Protect on a chain publishes it (no deployer key, no project funds)." },
  { id: "tron", name: "TRON", family: "TVM (Solidity)", set: "CCHS-K-20",
    addrStatus: "mainnet", pq: "contract",
    address: "base58check(0x41 ‖ keccak256(pk)[12:])",
    hash: "keccak256 opcode", storage: "same artifact", path: "evm/ (shared)",
    blurb: "TVM executes the EVM artifact unmodified (the TVM build is checked byte-identical in CI). CREATE2 uses prefix 0x41 instead of 0xff, so account addresses differ from the EVM ones and are predicted by tron/predict.mjs; there is no deterministic proxy on TRON, so the factory address depends on who publishes it. Not yet published on Nile or mainnet." },
  { id: "svm", name: "Solana", family: "Rust / Anchor", set: "CCHS-C-20",
    addrStatus: "mainnet", pq: "source",
    address: "base58(ed25519_pk)",
    hash: "sha256 syscall", storage: "PDA per (epoch, treeIdx)", path: "solana/, cchs-core/",
    blurb: "cchs-core is a no_std Rust crate implementing the verifier over an injected hash; it replays the shared vectors in CI. Solana uses CCHS-C-20 (n = 24, w = 256): cache_subtree registers a subtree, execute carries one 864 B layer plus the signer-chosen index and is sent as one v0 transaction with a lookup table (1 090 B of 1 232). Compute units measured in CI on the SBF build: execute 616–708 K for the fixture layers (≈ 180 CU per chain step), worst case ≈ 1.17 M, so each execute carries a compute-budget instruction. Not deployed." },
  { id: "cosmos", name: "Cosmos", family: "CosmWasm", set: "CCHS-S-20",
    addrStatus: "mainnet", pq: "source",
    address: "bech32(prefix, ripemd160(sha256(pk)))",
    hash: "sha2_256 (Rust)", storage: "Map<(u64,u64), [u8;32]>", path: "cosmwasm/, cchs-core/",
    blurb: "Same cchs-core crate; the contract adds a chain-id-bound digest and a storage map. Not deployed on any zone." },
  { id: "near", name: "NEAR", family: "near-sdk", set: "CCHS-S-20",
    addrStatus: "mainnet", pq: "source",
    address: "hex(ed25519_pk) implicit account",
    hash: "env::sha256", storage: "LookupMap", path: "near/, cchs-core/",
    blurb: "Implicit accounts are the raw key, so the derived address is a real account. The contract source uses cchs-core; one receipt (300 TGas) fits a signature comfortably on paper, not yet measured." },
  { id: "aptos", name: "Aptos", family: "Move", set: "CCHS-S-20",
    addrStatus: "mainnet", pq: "source",
    address: "sha3_256(pk ‖ 0x00)",
    hash: "aptos_std::hash::sha2_256", storage: "Table<u128, vector<u8>>", path: "aptos/sources/",
    blurb: "Move module with the same ADRS layout and digest construction, checked against the S-20 vectors by unit tests. Not published." },
  { id: "sui", name: "Sui", family: "Move 2024", set: "CCHS-S-20",
    addrStatus: "mainnet", pq: "source",
    address: "blake2b_256(0x00 ‖ pk)",
    hash: "std::hash::sha2_256", storage: "dynamic fields on a shared object", path: "sui/sources/",
    blurb: "Shared-object account; cache entries are dynamic fields keyed by (epoch, treeIdx). Vectors replayed in Move tests. Not published." },
  { id: "cairo", name: "Starknet", family: "Cairo 1", set: "CCHS-S-20",
    addrStatus: "preview", pq: "source",
    address: "account factory formula (preview)",
    hash: "core::sha256 (expensive in Cairo)", storage: "LegacyMap", path: "cairo/src/",
    blurb: "SHA-256 is costly in Cairo; a keccak or Poseidon-based set would be the natural fit here and is listed as an open problem in the spec. Source and test vectors exist." },
  { id: "ton", name: "TON", family: "FunC", set: "CCHS-S-20",
    addrStatus: "preview", pq: "source",
    address: "hash(StateInit) — preview shows the key",
    hash: "HASHEXT_SHA256", storage: "dict", path: "ton/contracts/",
    blurb: "FunC contract with the verifier in cell-based form. Real addresses need the StateInit computation. Not deployed." },
  { id: "bitcoin", name: "Bitcoin", family: "Tapscript", set: "WOTS+ tapleaf",
    addrStatus: "mainnet", pq: "blocked",
    address: "bc1q… (BIP-84) today; P2TR tree address from the builder",
    hash: "OP_SHA256", storage: "none (UTXO lineage)", path: "wallet/src/aegis/btcTapscript.ts",
    blurb: "The builder emits a Taproot tree of 2^h WOTS+ leaves and valid spend witnesses, checked against BIP-341 vectors. Without OP_CAT or OP_CHECKSIGFROMSTACK a script cannot bind the signed digits to the transaction, so there is no hash-only Bitcoin spend today." },
];

const PQ_TEXT: Record<Pq, { label: string; cls: string }> = {
  contract: { label: "pq: contract", cls: "live" },
  source:   { label: "pq: source",   cls: "soon" },
  blocked:  { label: "pq: blocked",  cls: "wait" },
};

/** Below this width the detail opens under the selected adapter (there is no hover, and a side panel would be off screen). */
const NARROW = "(max-width: 900px)";

function useNarrow(): boolean {
  const [narrow, setNarrow] = useState(() => typeof window !== "undefined" && window.matchMedia(NARROW).matches);
  useEffect(() => {
    const mq = window.matchMedia(NARROW);
    const on = () => setNarrow(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return narrow;
}

function Detail({ a, inline }: { a: Adapter; inline?: boolean }) {
  const pq = PQ_TEXT[a.pq];
  return (
    <div className={"arch-detail" + (inline ? " inline" : "")} role="region" aria-live="polite">
      <div className="arch-head">
        <div className="arch-detail-name">{a.name}</div>
        <div className="arch-stack">
          <span className={`arch-status ${a.addrStatus === "mainnet" ? "live" : "soon"}`}>addr: {a.addrStatus}</span>
          <span className={`arch-status ${pq.cls}`}>{pq.label}</span>
        </div>
      </div>
      <div className="mono arch-detail-set">{a.family} · {a.set}</div>
      <p>{a.blurb}</p>
      <div className="meta">
        <div><div className="k">Address</div><div className="v">{a.address}</div></div>
        <div><div className="k">Hash primitive</div><div className="v">{a.hash}</div></div>
        <div><div className="k">Cache storage</div><div className="v">{a.storage}</div></div>
        <div><div className="k">Path</div><div className="v">{a.path}</div></div>
      </div>
      {!inline && <div className="mono arch-hint">hover or tap an adapter</div>}
    </div>
  );
}

export default function ArchitectureDiagram() {
  const [sel, setSel] = useState<AdapterId>("evm");
  const narrow = useNarrow();
  const a = ADAPTERS.find((x) => x.id === sel)!;
  return (
    <div className="card arch">
      <div className="arch-stage">
        <div className="arch-col" role="group" aria-label="Seed and core">
          <div className="arch-col-label">Seed</div>
          <div className="arch-seed active">
            <div className="arch-head">
              <span className="arch-title">BIP-39 mnemonic</span>
              <span className="arch-status live">input</span>
            </div>
            <div className="arch-sub">PBKDF2-HMAC-SHA512 · 2048 rounds · 64 B seed</div>
          </div>
          <div className="arch-col-label" style={{ marginTop: 10 }}>Core</div>
          <div className="arch-core active">
            <div className="arch-head">
              <span className="arch-title">CCHS master</span>
              <span className="arch-status live">32 B</span>
            </div>
            <div className="arch-sub">
              HKDF-SHA256 · info "aegis/cchs/master/v1"<br />
              → a chain key per chain · info "…/chain/v1" ‖ tag<br />
              → K-20 tree (EVM) · S-20 / C-20 tree (others)<br />
              → every WOTS+ chain, derived on demand
            </div>
          </div>
          <div className="arch-core">
            <div className="arch-head">
              <span className="arch-title">Verifier</span>
              <span className="arch-status live">cache</span>
            </div>
            <div className="arch-sub">
              root, recRoot, epoch, nextIdx<br />
              cachedRoot[(epoch, treeIdx)]
            </div>
          </div>
        </div>

        <div className="arch-col" role="group" aria-label="Chain adapters">
          <div className="arch-col-label">Chain adapters</div>
          {ADAPTERS.map((x) => (
            <div key={x.id} className="arch-adapter-slot">
              <div className={"arch-adapter" + (sel === x.id ? " active" : "")}
                role="button" aria-pressed={sel === x.id} aria-controls="arch-detail"
                onMouseEnter={() => { if (!narrow) setSel(x.id); }} onFocus={() => setSel(x.id)} onClick={() => setSel(x.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSel(x.id); } }} tabIndex={0}>
                <div className="arch-head">
                  <span className="arch-title">{x.name}</span>
                  <div className="arch-stack">
                    <span className={`arch-status ${x.addrStatus === "mainnet" ? "live" : "soon"}`}>addr: {x.addrStatus}</span>
                    <span className={`arch-status ${PQ_TEXT[x.pq].cls}`}>{PQ_TEXT[x.pq].label}</span>
                  </div>
                </div>
                <div className="arch-sub">{x.family} · {x.set}</div>
              </div>
              {narrow && sel === x.id && <Detail a={x} inline />}
            </div>
          ))}
        </div>

        {!narrow && <div className="arch-detail-col"><Detail a={a} /></div>}
      </div>
    </div>
  );
}
