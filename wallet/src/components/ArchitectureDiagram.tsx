import { useState } from "react";

type AdapterId =
  | "evm" | "cairo" | "svm" | "cosmos" | "tron" | "aptos" | "sui" | "near" | "ton" | "bitcoin";

type Adapter = {
  id: AdapterId;
  name: string;
  family: string;
  status: "live" | "soon" | "wait";
  address: string;
  verify: string;
  effort: string;
  blurb: string;
};

const ADAPTERS: Adapter[] = [
  { id: "evm",     name: "EVM × 30+",   family: "Solidity",         status: "live",
    address: "CREATE address (deployer + nonce)", verify: "SPHINCS+ C13 · ~190K gas",
    effort: "shipped", blurb: "Same immutable bytecode deployed from the same deployer EOA at nonce 0 (verifier) and 1 (factory) yields identical addresses on every EVM chain." },
  { id: "cairo",   name: "Starknet",    family: "Cairo 1",          status: "live",
    address: "pedersen(class_hash, pk_hash, guardian)", verify: "Poseidon stub · real SPHINCS+ in v0.2",
    effort: "state machine shipped", blurb: "Native Starknet smart account with the same execute / initiate / cancel / finalize state machine, dispatching user calls through call_contract_syscall." },
  { id: "svm",     name: "Solana",      family: "Anchor / Rust",    status: "soon",
    address: "PDA(seed = [\"aegis-v1\", pk_hash, guardian])", verify: "SPHINCS+ via SIMD-0152 syscall or SHRINCS",
    effort: "~4 weeks", blurb: "Anchor program with full state machine. BPF's 200K compute-unit budget means verify needs either a precompile syscall or the SHRINCS variant (~324B sigs)." },
  { id: "cosmos",  name: "Cosmos",      family: "CosmWasm 2.1",     status: "soon",
    address: "bech32(prefix, sha256(pq_pk)[:20])", verify: "In-contract SHRINCS or host_sphincs_verify",
    effort: "~3 weeks", blurb: "Rust CosmWasm contract targeting Osmosis / Neutron / Injective / Archway. wasm32 build passes CI today." },
  { id: "tron",    name: "TRON",        family: "TVM (Solidity)",   status: "soon",
    address: "base58check(0x41 ‖ keccak256(ecdsa_pk)[12:])", verify: "Shares EVM artifact",
    effort: "~1 week", blurb: "TRON's TVM is EVM-compatible — same AegisAccount bytecode, only the base58check address encoding is new." },
  { id: "aptos",   name: "Aptos",       family: "Move",             status: "soon",
    address: "sha3_256(pq_pk ‖ 0x02)", verify: "aptos_std::sphincs (future) or SHRINCS",
    effort: "~6 weeks", blurb: "Move module with Resource layout. Finalize requires SignerCapability (resource account pattern)." },
  { id: "sui",     name: "Sui",         family: "Move 2024",        status: "soon",
    address: "blake2b_256(0xFE ‖ pq_pk)[:32]", verify: "Native SPHINCS+ (future) or SHRINCS",
    effort: "~6 weeks", blurb: "Shared-object account. 0xFE is a provisional multisig flag byte for SPHINCS+ pending Sui governance." },
  { id: "near",    name: "NEAR",        family: "near-sdk 5.5",     status: "soon",
    address: "hex(sha256(pq_pk)) implicit account", verify: "Fits in one receipt (300 TGas)",
    effort: "~4 weeks", blurb: "NEAR implicit accounts map 1-to-1 to hex(sha256(pk)). Full state machine + Promise dispatch." },
  { id: "ton",     name: "TON",         family: "FunC",             status: "soon",
    address: "hash(StateInit)", verify: "SHRINCS variant · TVM op split",
    effort: "~6 weeks", blurb: "TVM has a ~1M gas tx cap; plain SPHINCS+ exceeds it. We ship SHRINCS or split the hyper-tree across messages." },
  { id: "bitcoin", name: "Bitcoin",     family: "Taproot / BIP-360", status: "wait",
    address: "P2MR (post BIP-360 activation)", verify: "OP_SPHINCSVERIFY (companion BIP)",
    effort: "blocked", blurb: "Shipping on Bitcoin without BIP-360 would either expose a secp256k1 key path or force always-script-path spends. We wait." },
];

export default function ArchitectureDiagram() {
  const [sel, setSel] = useState<AdapterId>("evm");
  const a = ADAPTERS.find((x) => x.id === sel)!;
  return (
    <div className="card arch">
      <div className="arch-stage">
        <div className="arch-col">
          <h5>Seed</h5>
          <div className="arch-seed active">
            <div className="arch-head">
              <span className="arch-title">BIP-39 mnemonic</span>
              <span className="arch-status live">input</span>
            </div>
            <div className="arch-sub">24 words · PBKDF2-HMAC-SHA512 · 2048 rounds</div>
          </div>
          <h5 style={{ marginTop: 10 }}>Core</h5>
          <div className="arch-core active">
            <div className="arch-head">
              <span className="arch-title">aegis-core</span>
              <span className="arch-status live">rust · wasm</span>
            </div>
            <div className="arch-sub">
              HKDF-SHA512 → SPHINCS+ pk (48B) + sk (96B)<br />
              HKDF-SHA512 → secp256k1 fallback (32B)
            </div>
          </div>
        </div>

        <div className="arch-col">
          <h5>Chain adapters</h5>
          {ADAPTERS.map((x) => (
            <div
              key={x.id}
              className={"arch-adapter" + (sel === x.id ? " active" : "")}
              onMouseEnter={() => setSel(x.id)}
              onFocus={() => setSel(x.id)}
              onClick={() => setSel(x.id)}
              tabIndex={0}
            >
              <div className="arch-head">
                <span className="arch-title">{x.name}</span>
                <span className={`arch-status ${x.status}`}>{x.status === "live" ? "live" : x.status === "soon" ? "soon" : "waiting"}</span>
              </div>
              <div className="arch-sub">{x.family}</div>
            </div>
          ))}
        </div>

        <div className="arch-detail">
          <div className="arch-head">
            <h4>{a.name}</h4>
            <span className={`arch-status ${a.status}`}>{a.status === "live" ? "live" : a.status === "soon" ? "roadmap" : "waiting"}</span>
          </div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-3)" }}>{a.family}</div>
          <p>{a.blurb}</p>
          <div className="meta">
            <div><div className="k">Address derivation</div><div className="v">{a.address}</div></div>
            <div><div className="k">Verify path</div><div className="v">{a.verify}</div></div>
            <div><div className="k">Status</div><div className="v">{a.status === "live" ? "shipped" : "roadmap"}</div></div>
            <div><div className="k">Effort</div><div className="v">{a.effort}</div></div>
          </div>
          <div style={{ marginTop: "auto", fontSize: 11.5, color: "var(--text-4)", fontFamily: "var(--font-mono)" }}>
            hover any adapter · tap on mobile
          </div>
        </div>
      </div>
    </div>
  );
}
