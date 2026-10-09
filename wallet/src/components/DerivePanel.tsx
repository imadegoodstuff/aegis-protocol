import { useState } from "react";
import { isValidMnemonic } from "../aegis/derive";
import { useDerived } from "../aegis/useAegisWorker";
import CopyBtn from "./CopyBtn";
import PqSignDemo from "./PqSignDemo";
import SwapPanel  from "./SwapPanel";
import ProtectPanel from "./ProtectPanel";
import BitcoinPanel from "./BitcoinPanel";

// BIP-39 test vector for 32 zero bytes of entropy: 24 words, 256 bits. A 12-word
// phrase is accepted by the derivation demo but refused by the CCHS panel (§5.6 P4).
const SAMPLE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

const EVM_CHAINS = [
  "Ethereum", "BSC", "Polygon", "Arbitrum", "Optimism",
  "Base", "Avalanche", "Linea", "Scroll", "Mantle", "Blast", "Mode",
] as const;

export default function DerivePanel() {
  const [mnemonic, setMnemonic]   = useState(SAMPLE);
  const [passphrase, setPassphrase] = useState("");
  const [showPp, setShowPp] = useState(false);

  const valid = isValidMnemonic(mnemonic);
  const { addresses: result, loading, error } = useDerived(valid ? mnemonic : "", passphrase);

  return (
    <div className="card derive">
      <div className="derive-head">
        <div className="section-eyebrow">Step 1 · identity · computed in your browser</div>
        <h3>Enter a BIP-39 phrase.</h3>
        <p>
          It derives the CCHS master (hash-only account), an SLH-DSA-SHAKE-192s key (FIPS 205, for the
          hybrid account) and standard addresses for 25 chains. Everything runs in Web Workers; nothing
          leaves the page. The sample phrase is the public BIP-39 test vector for all-zero entropy (24 words); CCHS
          accounts require 24 words, because a hash-based account is only as strong as the seed behind it.
        </p>
      </div>

      <div className="derive-input">
        <label className="derive-label">
          <span>mnemonic (24 words for CCHS; 12 derive addresses only)</span>
          <textarea
            className="derive-area mono"
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            rows={2}
          />
          <div className="derive-sub-bar">
            <span>
              {valid
                ? <span style={{ color: "var(--accent)" }}>✓ valid BIP-39{loading && " · deriving…"}</span>
                : <span style={{ color: "var(--warn)" }}>✗ invalid phrase</span>}
            </span>
            <button className="link-btn" onClick={() => setMnemonic(SAMPLE)}>load sample →</button>
          </div>
        </label>

        <label className="derive-label">
          <span>passphrase (optional, BIP-39)</span>
          <div style={{ display: "flex", gap: 10 }}>
            <input
              className="derive-input-s"
              type={showPp ? "text" : "password"}
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="(empty)"
            />
            <button className="btn" onClick={() => setShowPp((v) => !v)}>{showPp ? "hide" : "show"}</button>
          </div>
        </label>
      </div>

      {error && (
        <div className="swap-note err" style={{ marginTop: 16 }}>
          Derivation error: {error}
        </div>
      )}

      {result && <ProtectPanel mnemonic={mnemonic} />}
      {result && <BitcoinPanel mnemonic={mnemonic} />}
      {result && <SwapPanel  mnemonic={mnemonic} />}
      {result && <PqSignDemo mnemonic={mnemonic} />}

      {result && (
        <div className="derive-out">
          <div className="derive-section">
            <div className="derive-section-head">
              <span className="section-eyebrow" style={{ color: "var(--accent)" }}>Identity</span>
              <span className="chip">real FIPS 205 keypair · deterministic from mnemonic</span>
            </div>
            <div className="kv">
              <KV label="pq_pk (SPHINCS+ public key, 48 B)"      val={result.pqPkHex} />
              <KV label="pq_pk_hash (keccak256 commitment)"      val={"0x" + result.pqPkHashHex} />
            </div>
          </div>

          <div className="derive-section">
            <div className="derive-section-head">
              <span className="section-eyebrow" style={{ color: "var(--accent)" }}>EVM — ECDSA address, the same on every EVM chain</span>
              <span className="chip chip-accent">secp256k1 (ECDSA) · not post-quantum · hybrid owner / fallback only</span>
            </div>
            <div className="addr-strip">
              <span className="addr-value">{result.evmAddress}</span>
              <CopyBtn value={result.evmAddress} />
            </div>
            <div className="chain-grid chain-grid-tight">
              {EVM_CHAINS.map((c) => (
                <div key={c} className="chain-cell">
                  <div className="chain-name">
                    <span className="chain-dot" /> <span className="chain-label">{c}</span>
                  </div>
                  <span className="chain-status ok mono">{short(result.evmAddress)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="derive-section">
            <div className="derive-section-head">
              <span className="section-eyebrow" style={{ color: "var(--accent-2)" }}>
                Non-EVM — standard ed25519 / secp256k1 addresses, importable to native wallets
              </span>
              <span className="chip chip-accent">not post-quantum · same seed · the hash-only account is under Protect</span>
            </div>
            <div className="kv">
              <KV label="Solana  ·  import to Phantom / Backpack"           val={result.solanaAddress} />
              <KV label="TRON  ·  import to TronLink"                       val={result.tronBase58} />
              <KV label="Osmosis  ·  import to Keplr"                       val={result.cosmosOsmo} />
              <KV label="Injective  ·  import to Keplr (Ethermint path)"    val={result.cosmosInj} />
              <KV label="Neutron  ·  import to Keplr / Leap"                val={result.cosmosNeutron} />
              <KV label="Juno  ·  import to Keplr / Leap"                   val={result.cosmosJuno} />
              <KV label="Stargaze  ·  import to Keplr / Leap"               val={result.cosmosStargaze} />
              <KV label="NEAR  ·  implicit account (ed25519)"               val={result.nearImplicit} />
              <KV label="Aptos  ·  import to Petra / Pontem"                val={result.aptosAddress} />
              <KV label="Sui  ·  import to Sui Wallet / Suiet"              val={result.suiAddress} />
              <KV label="Bitcoin mainnet  ·  BIP-84 P2WPKH, import to Sparrow (not post-quantum; the hash-only account runs on signet, above)" val={result.btcSegwit} />
              <KV label="TON  ·  ed25519 pubkey (preview; import secret to Tonkeeper)" val={result.tonPreview} />
            </div>
          </div>
        </div>
      )}

      {!result && valid && loading && (
        <div style={{
          marginTop: 20, padding: "24px 20px", background: "var(--ink-0)",
          border: "1px solid var(--line)", borderRadius: 8,
          color: "var(--text-3)", fontFamily: "var(--font-mono)", fontSize: 13,
          textAlign: "center"
        }}>
          generating real SLH-DSA-SHAKE-192s keypair in web-worker · ~2-3 s on first run
        </div>
      )}
    </div>
  );
}

function short(a: string) {
  return a.length > 14 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a;
}

function KV({ label, val }: { label: string; val: string }) {
  return (
    <div className="kv-row">
      <div className="kv-label">{label}</div>
      <div className="kv-val">
        <span>{val}</span>
        <CopyBtn value={val} />
      </div>
    </div>
  );
}
