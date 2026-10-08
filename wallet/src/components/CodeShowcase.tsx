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
    sol:   ["contract","function","public","external","view","pure","payable","returns","immutable","constant","mapping","uint256","address","bytes","bytes32","bool","if","else","require","revert","emit","struct","event","modifier","import","pragma","using","for","while","return","this","new","assembly","try","catch","override","virtual","private","internal","abstract","interface","is","library","fallback","receive","unchecked","type","memory","calldata","storage","days","years","hours"],
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

const TABS: Tab[] = [
  {
    id: "sol",
    label: "AegisAccount.sol",
    code: `// evm/src/AegisAccount.sol — core state machine
contract AegisAccount {
    bytes32 public immutable PQ_PK_HASH;
    address public immutable GUARDIAN;
    ISphincsVerifier public immutable VERIFIER;

    uint256 public constant  MAX_FEE_BPS      = 2000;   // 20% hard ceiling
    uint256 public constant  PROTOCOL_FEE_BPS = 1000;   // 10% of gas
    uint256 public constant  TIMELOCK         = 7 days;

    function execute(
        address target, uint256 value, bytes calldata data,
        uint256 providedNonce,
        bytes calldata pqPk, bytes calldata pqSig
    ) external payable returns (bytes memory result) {
        uint256 startGas = gasleft();
        _authorizePq(
            keccak256(abi.encode(block.chainid, address(this),
                                 providedNonce, target, value, data)),
            providedNonce, pqPk, pqSig
        );
        (bool ok, bytes memory r) = target.call{value: value}(data);
        require(ok, "AEG_CALL_FAILED");
        _collectFee(startGas);
        return r;
    }
}`,
  },
  {
    id: "rs",
    label: "core/lib.rs",
    code: `// core/src/lib.rs — one seed, every chain
pub fn identity_from_mnemonic(mnemonic: &str, passphrase: &str)
    -> Result<Identity, AegisError>
{
    let m    = Mnemonic::parse_normalized(mnemonic)?;
    let seed = m.to_seed(passphrase);
    let hk   = Hkdf::<Sha512>::new(None, &seed);

    // SPHINCS+-192s material (48 B pk + 96 B sk)
    let mut buf = [0u8; 144];
    hk.expand(SPHINCS_SEED_INFO, &mut buf)?;
    let pq_pk = buf[..48].to_vec();

    // Independent ECDSA fallback for the 7-day timelock exit path
    let mut sk = [0u8; 32];
    hk.expand(ECDSA_SEED_INFO, &mut sk)?;
    let signing = EcdsaSigningKey::from_slice(&sk)?;

    Ok(Identity { pq_pk, ecdsa_sk: sk, .. })
}`,
  },
  {
    id: "cairo",
    label: "cairo/lib.cairo",
    code: `// cairo/src/lib.cairo — Starknet account
#[starknet::contract]
pub mod AegisAccount {
    #[storage]
    struct Storage {
        pq_pk_hash:     felt252,
        guardian:       ContractAddress,
        verifier:       ContractAddress,
        nonce:          u64,
        exit_timestamp: u64,
    }

    #[abi(embed_v0)]
    impl AegisAccountImpl of super::IAegisAccount<ContractState> {
        fn execute(
            ref self: ContractState,
            target: ContractAddress, selector: felt252,
            calldata: Array<felt252>, provided_nonce: u64,
            pq_pk: Array<felt252>, pq_sig: Array<felt252>,
        ) {
            assert(provided_nonce == self.nonce.read() + 1, 'BAD_NONCE');
            let digest = poseidon_hash_span(buf.span());
            let v = ISphincsVerifierDispatcher {
                contract_address: self.verifier.read()
            };
            assert(v.verify(pq_pk, digest, pq_sig), 'INVALID_SIG');
            self.nonce.write(provided_nonce);
        }
    }
}`,
  },
  {
    id: "ts",
    label: "wallet/derive.ts",
    code: `// wallet/src/aegis/derive.ts — in-browser derivation
export function derive(mnemonic: string, passphrase = ""): Derived {
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase);

  // Match core/src/lib.rs byte-for-byte
  const pqPk    = hkdf(sha512, seed, undefined, SPHINCS_INFO, 144).slice(0, 48);
  const ecdsaSk = hkdf(sha512, seed, undefined, ECDSA_INFO,   32);
  const ecdsaPk = secp256k1.getPublicKey(ecdsaSk, false);

  return {
    evmAddress:   toChecksumAddr(keccak_256(ecdsaPk.slice(1)).slice(12)),
    cosmosOsmo:   bech32.encode("osmo", bech32.toWords(sha256(pqPk).slice(0,20))),
    nearImplicit: hexOf(sha256(pqPk)),
    tronBase58:   base58check(tronRaw),
  };
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
