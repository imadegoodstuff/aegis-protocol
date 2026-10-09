// The extension is the wallet's Protect / Spend surfaces behind a password:
// the mnemonic is decrypted into memory on unlock, the panels below are the
// same components the web wallet renders, and gas is paid by the mnemonic's
// own secp256k1 key instead of an injected wallet.

import { useEffect, useState } from "react";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { toHex } from "viem";
import { isValidMnemonic, mnemonicEntropyBits, CCHS_MIN_SEED_BITS, evmGasKey } from "@wallet/aegis/derive";
import { setLocalRelayer, localRelayerAddress, PROTECT_CHAINS, makePublicClient } from "@wallet/aegis/wallet";
import ProtectPanel from "@wallet/components/ProtectPanel";
import BitcoinPanel from "@wallet/components/BitcoinPanel";
import SolanaPanel from "@wallet/components/SolanaPanel";
import CopyBtn from "@wallet/components/CopyBtn";
import { createVault, destroyVault, hasVault, unlockVault } from "./vault";

type Screen = { kind: "loading" } | { kind: "create" } | { kind: "unlock" } | { kind: "open"; mnemonic: string };

export default function App() {
  const [screen, setScreen] = useState<Screen>({ kind: "loading" });

  useEffect(() => {
    hasVault().then((has) => setScreen(has ? { kind: "unlock" } : { kind: "create" }));
  }, []);

  // The gas key lives exactly as long as the mnemonic is in memory. It is set
  // before the panels render so they see the relayer on their first effect.
  const open = (mnemonic: string) => { setLocalRelayer(toHex(evmGasKey(mnemonic))); setScreen({ kind: "open", mnemonic }); };
  const lock = () => { setLocalRelayer(null); setScreen({ kind: "unlock" }); };
  useEffect(() => () => setLocalRelayer(null), []);

  return (
    <div className="ext">
      <header className="ext-head">
        <span className="ext-brand">AEGIS</span>
        <span className="ext-sub">hash-only accounts · no public key on chain</span>
        {screen.kind === "open" && <button className="btn btn-sm" onClick={lock}>Lock</button>}
      </header>
      {screen.kind === "loading" && <p className="ext-note">…</p>}
      {screen.kind === "create" && <Create onDone={open} />}
      {screen.kind === "unlock" && <Unlock onOpen={open} onReset={() => setScreen({ kind: "create" })} />}
      {screen.kind === "open" && <Wallet mnemonic={screen.mnemonic} />}
    </div>
  );
}

function Create({ onDone }: { onDone: (mnemonic: string) => void }) {
  const [mode, setMode] = useState<"new" | "import">("new");
  const [mnemonic, setMnemonic] = useState(() => generateMnemonic(wordlist, 256));
  const [pw, setPw] = useState(""); const [pw2, setPw2] = useState("");
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const valid = isValidMnemonic(mnemonic);
  const bits = valid ? mnemonicEntropyBits(mnemonic) : 0;

  async function go() {
    setErr(null);
    if (!valid) return setErr("that is not a valid BIP-39 phrase");
    if (bits < CCHS_MIN_SEED_BITS) return setErr(`a CCHS account needs a ${CCHS_MIN_SEED_BITS}-bit seed (24 words); this phrase has ${bits}`);
    if (pw.length < 8) return setErr("password: at least 8 characters");
    if (pw !== pw2) return setErr("passwords differ");
    if (mode === "new" && !saved) return setErr("confirm that you have written the phrase down");
    await createVault(mnemonic, pw);
    onDone(mnemonic.trim());
  }

  return (
    <section className="ext-card">
      <div className="ext-tabs">
        <button className={mode === "new" ? "on" : ""} onClick={() => { setMode("new"); setMnemonic(generateMnemonic(wordlist, 256)); }}>New account</button>
        <button className={mode === "import" ? "on" : ""} onClick={() => { setMode("import"); setMnemonic(""); }}>Import phrase</button>
      </div>
      {mode === "new" ? (
        <>
          <p className="ext-note">Write these 24 words down, in order, on paper. They are the only secret: every account on every chain, and the gas key, derive from them. Nobody can recover them for you.</p>
          <textarea className="ext-mnemonic" readOnly value={mnemonic} rows={4} />
          <div className="ext-row"><button className="btn btn-sm" onClick={() => setMnemonic(generateMnemonic(wordlist, 256))}>Generate another</button><CopyBtn value={mnemonic} /></div>
          <label className="ext-check"><input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> I have written the phrase down</label>
        </>
      ) : (
        <>
          <p className="ext-note">Paste a 24-word BIP-39 phrase. It is encrypted with your password and stored only in this extension.</p>
          <textarea className="ext-mnemonic" value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} rows={4} spellCheck={false} placeholder="word word word …" />
          {mnemonic && !valid && <p className="protect-err">not a valid phrase yet</p>}
        </>
      )}
      <label className="ext-field"><span>Password (unlocks this extension; never stored)</span><input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" /></label>
      <label className="ext-field"><span>Repeat password</span><input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" /></label>
      {err && <p className="protect-err">{err}</p>}
      <button className="btn btn-primary" onClick={go}>Create</button>
    </section>
  );
}

function Unlock({ onOpen, onReset }: { onOpen: (mnemonic: string) => void; onReset: () => void }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);

  async function go() {
    setBusy(true); setErr(null);
    const m = await unlockVault(pw);
    setBusy(false);
    if (!m) return setErr("wrong password");
    onOpen(m);
  }

  return (
    <section className="ext-card">
      <label className="ext-field"><span>Password</span>
        <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === "Enter" && go()} autoFocus autoComplete="current-password" />
      </label>
      {err && <p className="protect-err">{err}</p>}
      <button className="btn btn-primary" disabled={busy || !pw} onClick={go}>{busy ? "unlocking…" : "Unlock"}</button>
      <details className="ext-reset">
        <summary>Forgot the password?</summary>
        <p className="ext-note">The password only protects the copy of your phrase inside this extension. Remove it and import the phrase again from your paper backup. Your accounts and funds are on chain and are not affected.</p>
        {!confirmReset
          ? <button className="btn btn-sm" onClick={() => setConfirmReset(true)}>Remove stored phrase…</button>
          : <button className="btn btn-sm" onClick={async () => { await destroyVault(); onReset(); }}>Yes, remove it — I have the phrase on paper</button>}
      </details>
    </section>
  );
}

function Wallet({ mnemonic }: { mnemonic: string }) {
  const gas = localRelayerAddress();
  const [balances, setBalances] = useState<Record<number, bigint>>({});

  useEffect(() => {
    if (!gas) return;
    let cancelled = false;
    for (const chain of PROTECT_CHAINS) {
      makePublicClient(chain).getBalance({ address: gas }).then((b) => { if (!cancelled) setBalances((s) => ({ ...s, [chain.id]: b })); }).catch(() => {});
    }
    return () => { cancelled = true; };
  }, [gas]);

  const funded = PROTECT_CHAINS.filter((c) => (balances[c.id] ?? 0n) > 0n);

  return (
    <>
      <section className="ext-card ext-gas">
        <div className="section-eyebrow">Gas key · pays fees, holds nothing else</div>
        <div className="protect-tx mono">{gas} {gas && <CopyBtn value={gas} />}</div>
        <p className="ext-note">
          Every Protect and Spend below is a transaction somebody has to pay gas for. In the web wallet that is your MetaMask;
          here it is this address, derived from the same phrase. Send it a little of the native coin on each chain you use.
          It never holds your assets — those sit in the hash-only account — so a quantum break of this key costs you gas money, nothing more.
          {funded.length ? <> Funded on: {funded.map((c) => c.name).join(", ")}.</> : <> Not funded on any chain yet.</>}
        </p>
      </section>
      <ProtectPanel mnemonic={mnemonic} />
      <BitcoinPanel mnemonic={mnemonic} />
      <SolanaPanel mnemonic={mnemonic} />
      <p className="ext-note ext-foot">
        Solana moves need a Wallet Standard wallet (Phantom, Backpack) to pay fees; extension pages cannot see other extensions'
        wallets, so for Solana open the web wallet in a tab. Bitcoin signet needs no fee payer: the account UTXO pays its own fee.
      </p>
    </>
  );
}
