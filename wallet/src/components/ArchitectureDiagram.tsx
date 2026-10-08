import { useState } from "react";

type AdapterId =
  | "evm" | "cairo" | "svm" | "cosmos" | "tron" | "aptos" | "sui" | "near" | "ton" | "bitcoin";

type Status = "live" | "roadmap" | "wait";

type Adapter = {
  id: AdapterId;
  name: string;
  family: string;
  /** Address derivation: is a usable mainnet address derived + importable to native wallet? */
  addrStatus: "mainnet" | "preview";
  /** PQ smart-account on-chain layer: is the contract/program deployed? */
  pqStatus: Status;
  address: string;
  verify: string;
  effort: string;
  blurb: string;
};

const ADAPTERS: Adapter[] = [
  { id: "evm",     name: "EVM × 30+",   family: "Solidity",
    addrStatus: "mainnet", pqStatus: "roadmap",
    address: "CREATE address (deployer + nonce)",
    verify: "SPHINCS+ C13 vendored · ~190K gas verify",
    effort: "contract ready · pending Sepolia deploy (0.01 ETH to deployer)",
    blurb: "AegisAccountV2.sol + UpgradeHelper + Factory are production-ready. Address derivation is MAINNET today (standard ECDSA → importable to MetaMask). Deploy to Sepolia + any EVM mainnet is one env-var away."
  },
  { id: "cairo",   name: "Starknet",    family: "Cairo 1",
    addrStatus: "preview", pqStatus: "roadmap",
    address: "requires Argent/Braavos factory formula (preview)",
    verify: "Poseidon stub · real Cairo SPHINCS+ ~4 w",
    effort: "state machine shipped",
    blurb: "Native Starknet smart account with execute / exit state machine in Cairo. Address requires Argent-style account factory computation (adds starknet.js dep). PQ verifier in Cairo is a 4-week implementation."
  },
  { id: "svm",     name: "Solana",      family: "Anchor / Rust",
    addrStatus: "mainnet", pqStatus: "roadmap",
    address: "base58(ed25519_pk) — real Solana account",
    verify: "SPHINCS+ via SIMD-0152 syscall or SHRINCS",
    effort: "~4 weeks",
    blurb: "Address derivation uses standard ed25519 — importable to Phantom today. PQ account program needs either the SIMD-0152 user-precompile syscall or the SHRINCS variant to fit BPF compute budget."
  },
  { id: "cosmos",  name: "Cosmos",      family: "CosmWasm 2.1",
    addrStatus: "mainnet", pqStatus: "roadmap",
    address: "bech32(prefix, ripemd160(sha256(secp256k1_pk))) — standard",
    verify: "In-contract SHRINCS or host_sphincs_verify",
    effort: "~3 weeks",
    blurb: "Addresses are standard secp256k1 Cosmos — importable to Keplr today on Osmosis / Neutron / Juno / Stargaze. Injective uses the Ethermint variant. PQ contract is a Rust CosmWasm module."
  },
  { id: "tron",    name: "TRON",        family: "TVM (Solidity)",
    addrStatus: "mainnet", pqStatus: "roadmap",
    address: "base58check(0x41 ‖ keccak256(ecdsa_pk)[12:])",
    verify: "Shares EVM artifact",
    effort: "~1 week",
    blurb: "TVM is EVM-compatible — the AegisAccount Solidity bytecode works unmodified. Only the base58check address encoding differs. Address importable to TronLink today."
  },
  { id: "aptos",   name: "Aptos",       family: "Move",
    addrStatus: "mainnet", pqStatus: "roadmap",
    address: "sha3_256(ed25519_pk ‖ 0x00) — standard single-key scheme",
    verify: "aptos_std::sphincs (future) or SHRINCS",
    effort: "~6 weeks",
    blurb: "Standard ed25519 scheme byte 0x00. Importable to Petra / Pontem / Martian today. PQ Move module needs resource-account SignerCapability pattern."
  },
  { id: "sui",     name: "Sui",         family: "Move 2024",
    addrStatus: "mainnet", pqStatus: "roadmap",
    address: "blake2b_256(0x00 ‖ ed25519_pk) — standard flag",
    verify: "Native SPHINCS+ (future) or SHRINCS",
    effort: "~6 weeks",
    blurb: "Standard ed25519 flag byte 0x00. Importable to Sui Wallet / Suiet / Nightly. PQ account is a shared-object Move 2024 module."
  },
  { id: "near",    name: "NEAR",        family: "near-sdk 5.5",
    addrStatus: "mainnet", pqStatus: "roadmap",
    address: "hex(ed25519_pk) implicit account",
    verify: "Fits in one receipt (300 TGas)",
    effort: "~4 weeks",
    blurb: "NEAR implicit accounts ARE hex(ed25519_pk) — our derivation gives you one real mainnet account directly. Importable via near-cli. PQ contract is near-sdk Rust."
  },
  { id: "ton",     name: "TON",         family: "FunC",
    addrStatus: "preview", pqStatus: "roadmap",
    address: "needs StateInit cell hash (preview = ed25519 pubkey)",
    verify: "SHRINCS variant · TVM op split",
    effort: "~6 weeks",
    blurb: "Real TON wallet addresses require computing hash(StateInit) for Wallet v4R2 code+data cells — needs @ton/core (+50 KB). Users can import the ed25519 secret key to Tonkeeper directly."
  },
  { id: "bitcoin", name: "Bitcoin",     family: "Taproot / BIP-360",
    addrStatus: "mainnet", pqStatus: "wait",
    address: "bc1q + hash160(secp256k1_pk) — BIP-84 P2WPKH",
    verify: "OP_SPHINCSVERIFY (companion BIP, pending)",
    effort: "blocked on BIP-360 activation",
    blurb: "Address is a real BIP-84 SegWit v0 mainnet address — import to Sparrow / Electrum via WIF today. PQ layer blocked: without BIP-360 P2MR, hash-only authority on Bitcoin needs either key-path spend (secp256k1) or always-script-path (bad UX)."
  },
];

export default function ArchitectureDiagram() {
  const [sel, setSel] = useState<AdapterId>("evm");
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
            <div className="arch-sub">24 words · PBKDF2-HMAC-SHA512 · 2048 rounds</div>
          </div>
          <div className="arch-col-label" style={{ marginTop: 10 }}>Core</div>
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

        <div className="arch-col" role="group" aria-label="Chain adapters">
          <div className="arch-col-label">Chain adapters</div>
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
                <div className="arch-stack">
                  <span className={`arch-status ${x.addrStatus === "mainnet" ? "live" : "soon"}`}>
                    addr: {x.addrStatus === "mainnet" ? "MAINNET" : "PREVIEW"}
                  </span>
                  <span className={`arch-status ${x.pqStatus === "live" ? "live" : x.pqStatus === "roadmap" ? "soon" : "wait"}`}>
                    pq: {x.pqStatus === "live" ? "LIVE" : x.pqStatus === "roadmap" ? "ROADMAP" : "WAITING"}
                  </span>
                </div>
              </div>
              <div className="arch-sub">{x.family}</div>
            </div>
          ))}
        </div>

        <div className="arch-detail" role="region" aria-live="polite">
          <div className="arch-head">
            <div className="arch-detail-name">{a.name}</div>
            <div className="arch-stack">
              <span className={`arch-status ${a.addrStatus === "mainnet" ? "live" : "soon"}`}>
                addr: {a.addrStatus === "mainnet" ? "MAINNET" : "PREVIEW"}
              </span>
              <span className={`arch-status ${a.pqStatus === "live" ? "live" : a.pqStatus === "roadmap" ? "soon" : "wait"}`}>
                pq: {a.pqStatus === "live" ? "LIVE" : a.pqStatus === "roadmap" ? "ROADMAP" : "WAITING"}
              </span>
            </div>
          </div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-3)" }}>{a.family}</div>
          <p>{a.blurb}</p>
          <div className="meta">
            <div><div className="k">Address derivation</div><div className="v">{a.address}</div></div>
            <div><div className="k">Verify path</div><div className="v">{a.verify}</div></div>
            <div><div className="k">Status</div><div className="v">{a.pqStatus === "live" ? "shipped" : a.pqStatus === "roadmap" ? "roadmap" : "waiting"}</div></div>
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
