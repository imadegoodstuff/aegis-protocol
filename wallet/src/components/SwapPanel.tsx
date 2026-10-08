import { useEffect, useState, useMemo } from "react";
import type { Address, Hex } from "viem";
import { parseAbi, parseEther, formatEther, keccak256 } from "viem";
import {
  detectInjected, requestAccounts, getChainId, switchChain,
  makePublicClient, makeWalletClient, shortAddr, loadDeployment,
  SUPPORTED_CHAINS, DEFAULT_CHAIN, type Deployment,
} from "../aegis/wallet";
import { identity, isValidMnemonic } from "../aegis/derive";
import CopyBtn from "./CopyBtn";

const FACTORY_ABI = parseAbi([
  "function predictAddress(address owner, bytes32 pqPkHash) view returns (address)",
]);
const HELPER_ABI = parseAbi([
  "function upgrade(bytes32 pqPkHash, address[] erc20s) payable returns (address)",
  "function predict(address user, bytes32 pqPkHash) view returns (address)",
]);

type Status = "disconnected" | "connecting" | "wrong-chain" | "ready" | "upgrading" | "done";

export default function SwapPanel({ mnemonic }: { mnemonic: string }) {
  const [status, setStatus]     = useState<Status>("disconnected");
  const [account, setAccount]   = useState<Address | null>(null);
  const [chainId, setChainIdS]  = useState<number | null>(null);
  const [eoaBalance, setEoaBal] = useState<bigint | null>(null);
  const [deployment, setDep]    = useState<Deployment | null>(null);
  const [predicted, setPredicted] = useState<Address | null>(null);
  const [error, setError]       = useState<string | null>(null);
  const [txHash, setTxHash]     = useState<Hex | null>(null);
  const [ethToMove, setEthToMove] = useState("");

  const walletPresent = typeof window !== "undefined" && !!detectInjected();

  // Derive the user's PQ pubkey hash from mnemonic (real FIPS 205 SLH-DSA)
  const pqPkHash = useMemo<Hex | null>(() => {
    if (!isValidMnemonic(mnemonic)) return null;
    try {
      const id = identity(mnemonic);
      return keccak256(id.slhPublicKey);
    } catch { return null; }
  }, [mnemonic]);

  // When connected, read on-chain state
  useEffect(() => {
    (async () => {
      if (!account || !chainId) return;
      const chain = SUPPORTED_CHAINS[chainId];
      if (!chain) { setStatus("wrong-chain"); return; }
      const pub = makePublicClient(chain);
      try {
        const bal = await pub.getBalance({ address: account });
        setEoaBal(bal);
      } catch { /* ignore */ }
      const dep = await loadDeployment(chainId);
      setDep(dep);
      if (dep && pqPkHash) {
        try {
          const addr = await pub.readContract({
            address: dep.factory, abi: FACTORY_ABI, functionName: "predictAddress",
            args: [account, pqPkHash],
          }) as Address;
          setPredicted(addr);
        } catch { setPredicted(null); }
      }
      setStatus(dep ? "ready" : "wrong-chain");
    })();
  }, [account, chainId, pqPkHash]);

  // Subscribe to wallet events
  useEffect(() => {
    const eth = detectInjected();
    if (!eth || !eth.on) return;
    const onAccounts = (accs: unknown) => {
      const list = accs as string[];
      setAccount(list.length ? (list[0] as Address) : null);
      if (!list.length) setStatus("disconnected");
    };
    const onChain = (hex: unknown) => setChainIdS(parseInt(hex as string, 16));
    eth.on("accountsChanged", onAccounts);
    eth.on("chainChanged", onChain);
    return () => {
      eth.removeListener?.("accountsChanged", onAccounts);
      eth.removeListener?.("chainChanged", onChain);
    };
  }, []);

  async function connect() {
    try {
      setError(null); setStatus("connecting");
      const addr = await requestAccounts();
      const cid = await getChainId();
      setAccount(addr); setChainIdS(cid);
    } catch (e) {
      setError((e as Error).message);
      setStatus("disconnected");
    }
  }

  async function switchToSepolia() {
    try { await switchChain(DEFAULT_CHAIN.id); }
    catch (e) { setError((e as Error).message); }
  }

  async function doUpgrade() {
    if (!account || !chainId || !deployment || !pqPkHash) return;
    const chain = SUPPORTED_CHAINS[chainId];
    try {
      setError(null); setStatus("upgrading");
      const wc = makeWalletClient(chain, account);
      const value = ethToMove && Number(ethToMove) > 0 ? parseEther(ethToMove) : 0n;
      const hash = await wc.writeContract({
        address: deployment.upgradeHelper,
        abi: HELPER_ABI,
        functionName: "upgrade",
        args: [pqPkHash, []],
        value,
        chain,
        account,
      });
      setTxHash(hash);
      const pub = makePublicClient(chain);
      await pub.waitForTransactionReceipt({ hash });
      setStatus("done");
    } catch (e) {
      setError((e as Error).message);
      setStatus("ready");
    }
  }

  if (!walletPresent) {
    return (
      <div className="card swap-panel">
        <div className="swap-head">
          <div className="section-eyebrow">Upgrade · one-click</div>
          <h3>Make your assets quantum-safe.</h3>
          <p>Install <a href="https://metamask.io" target="_blank" rel="noreferrer">MetaMask</a>, <a href="https://rabby.io" target="_blank" rel="noreferrer">Rabby</a> or <a href="https://trust.io" target="_blank" rel="noreferrer">Trust Wallet</a>, then come back.</p>
        </div>
      </div>
    );
  }

  if (!pqPkHash) {
    return (
      <div className="card swap-panel">
        <div className="swap-head">
          <div className="section-eyebrow">Upgrade · one-click</div>
          <h3>Enter a BIP-39 mnemonic above</h3>
          <p>Your mnemonic derives the SPHINCS+ public-key commitment that will insure your account against ECDSA breaking.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card swap-panel">
      <div className="swap-head">
        <div className="section-eyebrow">Upgrade · one-click</div>
        <h3>Protect your assets with hash-only PQ insurance.</h3>
        <p>
          Deploys a per-user <code>AegisAccountV2</code> at a deterministic address,
          moves your assets in, and commits your SPHINCS+ public key hash. Daily
          operations stay ECDSA (fast). If ECDSA ever breaks, your pre-committed
          PQ key can recover the account via <code>pqRecover()</code>.
        </p>
      </div>

      <div className="swap-grid">
        <div className="swap-cell">
          <div className="k">Connected wallet</div>
          <div className="v">{account ? shortAddr(account) : "—"}</div>
        </div>
        <div className="swap-cell">
          <div className="k">Chain</div>
          <div className="v">{chainId ? (SUPPORTED_CHAINS[chainId]?.name ?? `chain ${chainId}`) : "—"}</div>
        </div>
        <div className="swap-cell">
          <div className="k">EOA balance</div>
          <div className="v">{eoaBalance != null ? `${formatEther(eoaBalance)} ETH` : "—"}</div>
        </div>
        <div className="swap-cell">
          <div className="k">Future Aegis address</div>
          <div className="v mono">{predicted ? shortAddr(predicted) : "—"}</div>
        </div>
      </div>

      <div className="swap-badges">
        <span className="chip chip-accent">SPHINCS+-192s pq_pk_hash: {pqPkHash.slice(0, 10)}…{pqPkHash.slice(-6)}</span>
      </div>

      {status === "disconnected" && (
        <button className="btn btn-primary swap-cta" onClick={connect}>
          Connect wallet
        </button>
      )}
      {status === "connecting" && (
        <button className="btn btn-primary swap-cta" disabled>connecting…</button>
      )}
      {status === "wrong-chain" && (
        <div className="swap-cta-group">
          <div className="swap-note warn">
            This chain ({chainId}) doesn't have Aegis contracts deployed yet.
            {deployment ? "" : ` Sepolia (${DEFAULT_CHAIN.id}) is where V2 is going live.`}
          </div>
          <button className="btn btn-primary swap-cta" onClick={switchToSepolia}>
            Switch to Sepolia
          </button>
        </div>
      )}
      {status === "ready" && (
        <div className="swap-cta-group">
          <label className="swap-amount">
            <span>ETH to move in</span>
            <input
              type="number" step="0.001" min="0" placeholder="0.0"
              value={ethToMove} onChange={(e) => setEthToMove(e.target.value)}
            />
            <span className="hint">leave empty = just deploy account</span>
          </label>
          <button className="btn btn-primary swap-cta" onClick={doUpgrade}>
            ⚡ Upgrade to post-quantum
          </button>
        </div>
      )}
      {status === "upgrading" && (
        <button className="btn btn-primary swap-cta" disabled>
          upgrading… {txHash && <span className="mono"> · {shortAddr(txHash)}</span>}
        </button>
      )}
      {status === "done" && predicted && (
        <div className="swap-done">
          <div className="done-head">✓ Your Aegis account is live</div>
          <div className="done-row">
            <span>Address</span>
            <span className="mono">{predicted}</span>
            <CopyBtn value={predicted} />
          </div>
          {txHash && (
            <div className="done-row">
              <span>Tx</span>
              <span className="mono">{txHash}</span>
              <CopyBtn value={txHash} />
            </div>
          )}
          <div className="done-note">
            Any future ETH / ERC-20 sent to this address is protected by your
            SPHINCS+ public key commitment. If ECDSA ever becomes forgeable,
            call <code>pqRecover()</code> with the signed digest.
          </div>
        </div>
      )}

      {error && <div className="swap-note err">{error}</div>}

      {!deployment && account && (
        <div className="swap-pending">
          <div className="k">Aegis V2 Sepolia deploy pending — fund the deployer:</div>
          <div className="v mono">0x67bb01F5DA6BD332Fa50271B2F4FF4957Cbe629C</div>
          <div className="hint">
            Any Sepolia ETH (0.01+) sent here lets us deploy the public V2 contracts.
            Watch this address on <a href="https://sepolia.etherscan.io/address/0x67bb01F5DA6BD332Fa50271B2F4FF4957Cbe629C" target="_blank" rel="noreferrer">Etherscan</a>.
          </div>
        </div>
      )}
    </div>
  );
}
