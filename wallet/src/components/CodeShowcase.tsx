import { useState } from "react";

type Lang = "sol" | "rs" | "cairo" | "ts";
type Tab  = { id: Lang; label: string; code: string };

// Two-pass tokenizer. Pass 1: carve comments/strings/numbers into opaque
// placeholders so subsequent passes don't re-match their contents. Pass 2:
// highlight keywords/types/functions on the remaining plain text. Pass 3:
// restore the carved tokens as wrapped spans. Then escape HTML.
function highlight(src: string, lang: Lang): string {
  type Tok = { kind: "cm" | "str" | "num"; text: string };
  const toks: Tok[] = [];
  // Fixed 2-letter base-26 index so digit regexes can't eat it.
  const enc = (n: number): string =>
    String.fromCharCode(97 + (n % 26)) + String.fromCharCode(97 + Math.floor(n / 26));
  const PH = (i: number) => `\u0001${enc(i)}\u0002`;

  const carve = (re: RegExp, kind: Tok["kind"], s: string) =>
    s.replace(re, (m) => { toks.push({ kind, text: m }); return PH(toks.length - 1); });

  let s = src;
  s = carve(/\/\/[^\n]*/g, "cm", s);
  s = carve(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, "str", s);
  s = carve(/\b(0x[0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:u\d+|i\d+)?)\b/g, "num", s);

  // escape HTML on the pre-carved text
  s = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const kwSets: Record<Lang, string[]> = {
    sol:   ["contract","function","public","external","view","pure","payable","returns","immutable","constant","mapping","uint256","uint64","uint32","uint8","address","bytes","bytes32","bool","error","event","if","else","require","revert","emit","struct","event","modifier","import","pragma","using","for","while","return","this","new","assembly","try","catch","override","virtual","private","internal","abstract","interface","is","library","fallback","receive","unchecked","type","memory","calldata","storage","days","years","hours"],
    rs:    ["pub","fn","let","mut","const","static","if","else","match","return","use","mod","struct","enum","impl","trait","for","in","while","loop","break","continue","async","await","dyn","as","self","Self","where","type","unsafe","ref","crate","extern","move","try"],
    cairo: ["pub","fn","mod","use","struct","enum","impl","trait","for","in","while","loop","if","else","match","return","let","mut","const","as","self","Self","where","type","super","assert","contract","interface","storage","constructor","felt252","u64","u16","u8","u32","u128","u256","bool","true","false"],
    ts:    ["const","let","var","function","return","if","else","for","while","switch","case","default","class","extends","implements","interface","type","enum","import","export","from","as","new","this","typeof","instanceof","true","false","null","undefined","void","async","await","try","catch","finally","throw","break","continue","in","of","do","yield","static","public","private","protected","readonly"],
  };
  const kws = kwSets[lang];
  s = s.replace(new RegExp(`\\b(${kws.join("|")})\\b`, "g"), (m) => `<span class="kw">${m}</span>`);

  // function definitions / calls
  s = s.replace(/\b(fn|function)\s+([a-zA-Z_][A-Za-z0-9_]*)/g,
    (_m, kw, n) => `<span class="kw">${kw}</span> <span class="fn">${n}</span>`);
  s = s.replace(/\.([a-z_][A-Za-z0-9_]*)(?=\()/g, (_m, n) => `.<span class="fn">${n}</span>`);

  // PascalCase as types (don't touch placeholders)
  s = s.replace(/\b([A-Z][A-Za-z0-9_]+)\b/g, (m) =>
    m.startsWith("\u0001") ? m : `<span class="ty">${m}</span>`);

  // restore tokens — decode 2-letter base-26 index
  s = s.replace(/\u0001([a-z])([a-z])\u0002/g, (_m, a: string, b: string) => {
    const idx = (a.charCodeAt(0) - 97) + (b.charCodeAt(0) - 97) * 26;
    const t = toks[idx];
    const escaped = t.text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return `<span class="${t.kind}">${escaped}</span>`;
  });
  return s;
}

// Excerpts of the files named in each tab. They are kept in step with the
// sources by hand; the contracts and the client are the authority.
const TABS: Tab[] = [
  {
    id: "sol",
    label: "evm/AegisCCHSBase.sol",
    code: `// evm/src/AegisCCHSBase.sol — the verifier is the account
abstract contract AegisCCHSBase {
    bytes32 public root;      // top-layer tree root, rotated only by recover
    bytes32 public recRoot;   // recovery tree root (height 8)
    uint64  public epoch;     // bumped by every recovery; namespaces the cache
    uint64  public nextIdx;   // next unused leaf in [0, 2^20)
    uint64  public nonce;
    /// key = (epoch << 64) | bottomTreeIdx
    mapping(uint256 => bytes32) public cachedRoot;

    /// Cached path: one WOTS+ signature and one auth path, 2 464 B.
    function execute(address target, uint256 value, bytes calldata data,
                     uint64 idx, LayerSig calldata l0)
        external returns (bytes memory result)
    {
        bytes32 m  = _begin(idx, target, value, data);   // idx >= nextIdx
        bytes32 r0 = _layerRoot(0, idx >> H, uint32(idx & (LEAVES - 1)), m, l0);
        bytes32 cached = cachedRoot[_cacheKey(idx >> H)];
        if (cached == bytes32(0)) revert MissingTopLayer();
        if (cached != r0)         revert BadSubtreeRoot();
        return _finish(idx, target, value, data);        // nextIdx = idx + 1
    }

    /// First operation in a subtree: also carries the top-layer proof,
    /// which is verified against \`root\` once and cached.
    function executeFirst(address target, uint256 value, bytes calldata data,
                          uint64 idx, LayerSig calldata l0, LayerSig calldata l1)
        external returns (bytes memory result)
    {
        bytes32 m  = _begin(idx, target, value, data);
        uint64 treeIdx = idx >> H;
        bytes32 r0 = _layerRoot(0, treeIdx, uint32(idx & (LEAVES - 1)), m, l0);
        uint256 key = _cacheKey(treeIdx);
        if (cachedRoot[key] == bytes32(0)) {
            if (_layerRoot(1, 0, uint32(treeIdx), r0, l1) != root) revert BadTopRoot();
            cachedRoot[key] = r0;
            emit SubtreeCached(epoch, treeIdx, r0);
        } else if (cachedRoot[key] != r0) revert BadSubtreeRoot();
        return _finish(idx, target, value, data);
    }
}`,
  },
  {
    id: "rs",
    label: "cchs-core/lib.rs",
    code: `// cchs-core/src/lib.rs — no_std verifier over an injected hash
// (Solana, CosmWasm and NEAR share this crate)

/// Complete every WOTS+ chain from the signature value to its end and
/// compress the 67 chain ends into the leaf: H(ADRS_leaf ‖ pk_0 ‖ … ‖ pk_66).
pub fn wots_leaf<S: Sha256>(
    h: &mut S, layer: u8, tree_idx: u64, leaf_idx: u32,
    msg: &[u8; 32], wots: &[[u8; 32]; LEN],
) -> [u8; 32] {
    let d = digits(msg);                       // 64 message + 3 checksum digits
    let mut leaf = S::default();
    leaf.update(&adrs(layer, tree_idx, TYPE_LEAF, leaf_idx, 0, 0));

    let mut a = adrs(layer, tree_idx, TYPE_CHAIN, leaf_idx, 0, 0);
    for c in 0..LEN {
        let mut x = wots[c];
        a[14] = c as u8;
        let mut s = d[c];
        while s < (W - 1) as u8 {              // w − 1 − digit steps
            a[15] = s;
            h.update(&a); h.update(&x);
            x = h.finish();
            s += 1;
        }
        leaf.update(&x);
    }
    leaf.finish()
}

/// Root of tree (layer, tree_idx) from a WOTS+ signature on \`msg\` and
/// its authentication path. Equal to the cached root, or to \`root\`.
pub fn verify_layer<S: Sha256>(
    h: &mut S, layer: u8, tree_idx: u64, leaf_idx: u32,
    msg: &[u8; 32], wots: &[[u8; 32]; LEN], auth: &[[u8; 32]], height: usize,
) -> [u8; 32] {
    let leaf = wots_leaf(h, layer, tree_idx, leaf_idx, msg, wots);
    root_from_path(h, layer, tree_idx, leaf, leaf_idx, &auth[..height])
}`,
  },
  {
    id: "cairo",
    label: "cairo/lib.cairo",
    code: `// cairo/src/lib.cairo — Starknet account, same state machine
#[starknet::contract]
pub mod AegisCCHS {
    #[storage]
    struct Storage {
        root:        u256,
        rec_root:    u256,
        epoch:       u64,
        next_idx:    u64,
        nonce:       u64,
        rec_nonce:   u64,
        cached_root: Map<(u64, u64), u256>,   // (epoch, tree_idx)
    }

    #[abi(embed_v0)]
    impl AegisCCHSImpl of super::IAegisCCHS<ContractState> {
        fn execute(
            ref self: ContractState,
            calls: Array<Call>, idx: u64,
            l0_wots: Array<u256>, l0_auth: Array<u256>,
            l1_wots: Array<u256>, l1_auth: Array<u256>,
        ) -> Array<Span<felt252>> {
            self.check_index(idx);                      // idx >= next_idx
            let m = self.execute_digest(idx, calls.span());
            self.verify_and_cache(idx, m, l0_wots.span(), l0_auth.span(),
                                  l1_wots.span(), l1_auth.span());
            self.advance(idx);                          // effects first

            let mut results = array![];
            for call in calls.span() {
                results.append(
                    call_contract_syscall(*call.to, *call.selector, *call.calldata)
                        .unwrap_syscall());
            };
            self.emit(Executed { idx, n_calls: calls.len() });
            results
        }
    }
}`,
  },
  {
    id: "ts",
    label: "wallet/cchsAccount.ts",
    code: `// wallet/src/aegis/cchsAccount.ts — one mnemonic, one key tree per chain
const MASTER_INFO = utf8("aegis/cchs/master/v1");
const CHAIN_INFO  = utf8("aegis/cchs/chain/v1");

export function cchsMaster(mnemonic: string, passphrase = ""): CchsKey {
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase);
  return { master: hkdf(sha256, seed, undefined, MASTER_INFO, 32) };
}

/** 0x00 ‖ chainId as u64 big-endian (EVM); 0x01 ‖ utf8(label) elsewhere. */
export function evmChainTag(chainId: number | bigint): Uint8Array {
  const tag = new Uint8Array(9);
  new DataView(tag.buffer).setBigUint64(1, BigInt(chainId));
  return tag;
}

/** A WOTS+ leaf signs one message, so no two chains may share a tree. */
export function chainKey(master: CchsKey, tag: Uint8Array): CchsKey {
  const info = concat(CHAIN_INFO, tag);
  return { master: hkdf(sha256, master.master, undefined, info, 32) };
}

/** Mirrors AegisCCHSFactory.predict; no RPC needed. */
export function predictAccount(root: Hex, recRoot: Hex, variant: Variant): Address {
  const initCode = concatHex([creationCode(variant), encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }], [root, recRoot])]);
  const salt = keccak256(concatHex([root, recRoot, variant === "S" ? "0x01" : "0x00"]));
  return getContractAddress({ opcode: "CREATE2", from: FACTORY_ADDRESS, salt, bytecode: initCode });
}`,
  },
];

export default function CodeShowcase() {
  const [active, setActive] = useState<Lang>("sol");
  const t = TABS.find((x) => x.id === active)!;
  return (
    <div className="card code-showcase">
      <div className="code-tabs">
        {TABS.map((x) => (
          <button
            key={x.id}
            className={"code-tab" + (active === x.id ? " active" : "")}
            onClick={() => setActive(x.id)}
          >
            <span className={`lang-dot ${x.id}`} /> {x.label}
          </button>
        ))}
      </div>
      <div className="code-body">
        <pre dangerouslySetInnerHTML={{ __html: highlight(t.code, t.id) }} />
      </div>
    </div>
  );
}
