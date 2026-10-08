import { useMemo, useState } from "react";
import { derive, isValidMnemonic, type Derived } from "../aegis/derive";
import CopyBtn from "./CopyBtn";

const SAMPLE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const EVM_CHAINS = [
  "Ethereum", "BSC", "Polygon", "Arbitrum", "Optimism",
  "Base", "Avalanche", "Linea", "Scroll", "Mantle", "Blast", "Mode",
] as const;

export default function DerivePanel() {
  const [mnemonic, setMnemonic]   = useState(SAMPLE);
  const [passphrase, setPassphrase] = useState("");
  const [showPp, setShowPp] = useState(false);

  const result = useMemo<Derived | null>(() => {
    if (!isValidMnemonic(mnemonic)) return null;
    try { return derive(mnemonic, passphrase); } catch { return null; }
  }, [mnemonic, passphrase]);

  return (
    <div className="card derive">
      <div className="derive-head">
        <div className="section-eyebrow">Live derivation · in your browser</div>
        <h3>Type a BIP-39 phrase · see your Aegis addresses on every chain</h3>
        <p>
          Nothing leaves your browser. No network call. Open DevTools and verify.
          The sample phrase is the well-known Hardhat / Foundry test vector; safe to use.
        </p>
      </div>

      <div className="derive-input">
        <label className="derive-label">
          <span>mnemonic (12 / 24 words)</span>
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
              {isValidMnemonic(mnemonic)
                ? <span style={{ color: "var(--lime)" }}>✓ valid BIP-39</span>
                : <span style={{ color: "var(--rose)" }}>✗ invalid phrase</span>}
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

      {result && (
        <div className="derive-out">
          <div className="derive-section">
            <div className="derive-section-head">
              <span className="section-eyebrow" style={{ color: "var(--cyan)" }}>Identity</span>
              <span className="chip">deterministic from mnemonic</span>
            </div>
            <div className="kv">
              <KV label="pq_pk (SPHINCS+ public key, 48B)" val={result.pqPkHex} />
              <KV label="pq_pk_hash (keccak256 commitment)" val={"0x" + result.pqPkHashHex} />
            </div>
          </div>

          <div className="derive-section">
            <div className="derive-section-head">
              <span className="section-eyebrow" style={{ color: "var(--lime)" }}>EVM — same address on 30+ chains</span>
              <span className="chip chip-grad">ECDSA fallback owner address</span>
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
              <span className="section-eyebrow" style={{ color: "var(--iris)" }}>Non-EVM — independent per family</span>
              <span className="chip">same seed · different derivation</span>
            </div>
            <div className="kv">
              <KV label="Osmosis (bech32 osmo1…)"    val={result.cosmosOsmo} />
              <KV label="Injective (bech32 inj1…)"   val={result.cosmosInj} />
              <KV label="Neutron (bech32 neutron1…)" val={result.cosmosNeutron} />
              <KV label="NEAR implicit account"      val={result.nearImplicit} />
              <KV label="TRON (base58check T…)"      val={result.tronBase58} />
              <KV label="TRON raw 21B (hex)"         val={result.tronRawHex} />
            </div>
          </div>
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
