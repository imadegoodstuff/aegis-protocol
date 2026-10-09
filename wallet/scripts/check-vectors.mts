// Replays the shared test vectors against the TypeScript client.
//
//   cchs-derivation.json  mnemonic -> seed -> master -> sk(0,0,0,0) -> roots -> EVM account (S-20, K-20)
//   cchs-s-20.json        roots, bottom roots, every op digest and signature, recovery
//   cchs-k-20.json        same for K-20
//
// A client that fails this script derives different keys or accepts different
// signatures than the reference and is not compatible with it. Run with
// `npm run vectors`; CI runs it on every push.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { keccak256 } from 'viem';
import * as cchs from '../src/aegis/cchs.ts';
import { cchsMaster, predictAccount } from '../src/aegis/cchsAccount.ts';

const fixtures = fileURLToPath(new URL('../../evm/test/fixtures/', import.meta.url));
const load = (name: string) => JSON.parse(readFileSync(fixtures + name, 'utf8'));
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));
let failures = 0;
const check = (what: string, got: string, want: string) => {
  const ok = got.toLowerCase() === want.toLowerCase();
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${ok ? '' : `\n       got  ${got}\n       want ${want}`}`);
};

// 1. derivation
{
  const d = load('cchs-derivation.json');
  const key = cchsMaster(d.mnemonic, d.passphrase);
  check('derivation master', cchs.toHex(key.master), d.master);
  for (const v of ['S', 'K'] as const) {
    const set = d.sets[v === 'S' ? 'CCHS-S-20' : 'CCHS-K-20'];
    const c = cchs.forVariant(v);
    const cache = new Map<string, cchs.Tree>();
    const pub = c.keygen(key, cache);
    check(`${v}-20 sk(0,0,0,0)`, cchs.toHex(cchs.sk(key, 0, 0n, 0, 0, v)), set.sk_0_0_0_0);
    check(`${v}-20 root`, cchs.toHex(pub.root), set.root);
    check(`${v}-20 recRoot`, cchs.toHex(pub.recRoot), set.recRoot);
    check(`${v}-20 bottomRoot0`, cchs.toHex(c.buildTree(key, 0, 0n, cchs.H).root), set.bottomRoot0);
    check(`${v}-20 EVM account`, predictAccount(set.root, set.recRoot, v), set.evmAccount);
  }
}

// 2. signature vectors
for (const v of ['S', 'K'] as const) {
  const f = load(`cchs-${v.toLowerCase()}-20.json`);
  const c = cchs.forVariant(v);
  const key: cchs.CchsKey = { master: fromHex(f.master) };
  const cache = new Map<string, cchs.Tree>();
  const pub = c.keygen(key, cache);
  check(`${v}-20 fixture root`, cchs.toHex(pub.root), f.root);
  check(`${v}-20 fixture recRoot`, cchs.toHex(pub.recRoot), f.recRoot);
  check(`${v}-20 fixture bottomRoot0`, cchs.toHex(c.buildTree(key, 0, 0n, cchs.H).root), f.bottomRoot0);
  check(`${v}-20 fixture bottomRoot1`, cchs.toHex(c.buildTree(key, 0, 1n, cchs.H).root), f.bottomRoot1);
  const account = fromHex(f.account);
  for (const op of [...f.ops, ...f.skip.ops]) {
    const m = c.executeDigest({ chainId: BigInt(f.chainId), account, nonce: BigInt(op.nonce), idx: BigInt(op.idx), target: fromHex(op.target), value: BigInt(op.value), dataHash: fromHex(keccak256(op.data)) });
    check(`${v}-20 digest idx ${op.idx}`, cchs.toHex(m), op.digest);
    const s = c.sign(key, op.idx, m, op.l1 === null, cache);
    check(`${v}-20 signature idx ${op.idx} (first chain value)`, cchs.toHex(s.l0.wots[0]), op.l0.wots[0]);
    check(`${v}-20 signature idx ${op.idx} (last auth node)`, cchs.toHex(s.l0.auth[cchs.H - 1]), op.l0.auth[cchs.H - 1]);
    if (op.l1) check(`${v}-20 top layer idx ${op.idx}`, cchs.toHex(s.l1!.wots[0]), op.l1.wots[0]);
  }
  const r = f.recovery;
  const rm = c.recoveryDigest({ chainId: BigInt(f.chainId), account, recNonce: BigInt(r.recNonce), newRoot: fromHex(r.newRoot), newRecRoot: fromHex(r.newRecRoot) });
  check(`${v}-20 recovery digest`, cchs.toHex(rm), r.digest);
  const rs = c.signRecovery(key, r.recNonce, rm, cache);
  check(`${v}-20 recovery signature`, cchs.toHex(rs.wots[0]), r.wots[0]);
}

if (failures) { console.log(`${failures} check(s) failed`); process.exit(1); }
console.log('all vectors reproduced');
