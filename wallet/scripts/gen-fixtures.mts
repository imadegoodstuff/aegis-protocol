// Regenerates the shared test vectors in evm/test/fixtures from the TypeScript
// client. Every other implementation (Solidity, Rust, Cairo, FunC, Move, the
// Solana program) replays these files, so a change to the hashing, the ADRS
// layout, the digests or the key derivation is made here first and then
// carried to each port until its tests pass again.
//
//   npm run gen-fixtures          # writes cchs-s-20.json, cchs-k-20.json, cchs-c-20.json, cchs-derivation.json
//
// Masters: 0x07..07 for the signing fixtures, 0x09..09 for the key the
// recovery vector rotates to; the derivation vector starts from the BIP-39
// test mnemonic. Cairo, Sui and Aptos embed a subset of the S-20 values in
// their sources (see each test module); `npm run vectors` checks that the
// wallet still reproduces all four files.

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { keccak256 } from 'viem';
import { sha256 } from '@noble/hashes/sha256';
import { mnemonicToSeedSync } from '@scure/bip39';
import * as cchs from '../src/aegis/cchs.ts';
import * as C from '../src/aegis/cchsCompact.ts';
import { cchsMaster, chainKey, evmChainTag, labelChainTag, predictAccount } from '../src/aegis/cchsAccount.ts';

const here = dirname(fileURLToPath(import.meta.url));
const out = (name: string) => resolve(here, '../../evm/test/fixtures', name);
const hex = cchs.toHex;
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));
const write = (name: string, obj: unknown) => { writeFileSync(out(name), JSON.stringify(obj, null, 1) + '\n'); console.log('wrote', name); };

const MASTER = { master: fromHex('0x' + '07'.repeat(32)) };
const NEXT_MASTER = { master: fromHex('0x' + '09'.repeat(32)) };
const LANE_FIRST = 1 << 16; // lane 1 (LANE_BITS = 4, 2H = 20)

// ----------------------------------------------------------- S-20 and K-20
{
  const chainId = 1n;
  const account = '0x000000000000000000000000000000000000cc45';
  const target = '0x000000000000000000000000000000000000beef';
  const value = 10n ** 18n;
  const data = '0x';
  for (const variant of ['S', 'K'] as const) {
    const c = cchs.forVariant(variant);
    const cache = new Map<string, cchs.Tree>();
    const pub = c.keygen(MASTER, cache);
    const op = (idx: number, nonce: number, cached: boolean) => {
      const m = c.executeDigest({ chainId, account: fromHex(account), nonce: BigInt(nonce), idx: BigInt(idx), target: fromHex(target), value, dataHash: fromHex(keccak256(data)) });
      const s = c.sign(MASTER, idx, m, cached, cache);
      return {
        idx, nonce, target, value: value.toString(), data, digest: hex(m),
        l0: { wots: s.l0.wots.map(hex), auth: s.l0.auth.map(hex) },
        l1: s.l1 ? { wots: s.l1.wots.map(hex), auth: s.l1.auth.map(hex) } : null,
      };
    };
    const ops = [op(0, 0, false), op(1, 1, true), op(2, 2, true)];
    // Signer-chosen index: after op 0, skip to leaf 5 inside subtree 0 (cached),
    // then jump to leaf 1024 = first leaf of subtree 1 (needs its top layer).
    const skip = { ops: [op(5, 1, true), op(1024, 2, false)] };
    const newPub = c.keygen(NEXT_MASTER);
    const recDigest = c.recoveryDigest({ chainId, account: fromHex(account), recNonce: 0n, newRoot: newPub.root, newRecRoot: newPub.recRoot, newSeed: newPub.seed });
    const rec = c.signRecovery(MASTER, 0, recDigest, cache);
    const laneOp = op(LANE_FIRST, 0, false);
    write(`cchs-${variant.toLowerCase()}-20.json`, {
      paramSet: variant === 'S' ? 'CCHS-S-20' : 'CCHS-K-20',
      hash: variant === 'S' ? 'sha256' : 'keccak256',
      adrs: 'layer(1) || treeIdx(8) || type(1) || leafIdx(4) || chainIdx(1) || step(1) || pkSeed(16)',
      seedInfo: variant === 'S' ? 'cchs/pkseed' : 'cchs/pkseed/k',
      master: hex(MASTER.master), chainId: Number(chainId), account,
      root: hex(pub.root), recRoot: hex(pub.recRoot), seed: hex(pub.seed), bottomRoot0: hex(cache.get('0/0')!.root),
      ops,
      bottomRoot1: hex(cache.get('0/1')!.root),
      skip,
      recovery: { recNonce: 0, newRoot: hex(newPub.root), newRecRoot: hex(newPub.recRoot), newSeed: hex(newPub.seed), digest: hex(recDigest), wots: rec.wots.map(hex), auth: rec.auth.map(hex) },
      lane: {
        note: 'Lane 1 (LANE_BITS = 4): first leaf 65 536 = bottom tree 64, leaf 0, lane nonce 0, with the top layer.',
        bottomRoot: hex(cache.get('0/64')!.root),
        ops: [laneOp],
      },
    });
  }
}

// ------------------------------------------------------------------- C-20
{
  const cache = new Map<string, cchs.Tree>();
  const pub = C.keygen(MASTER, cache);
  const account = new Uint8Array(32).fill(0xcc);
  const callHash = sha256(new Uint8Array([1, 2, 3]));
  const msg = (idx: number, nonce: number) => C.executeDigest({ tag: 'solana', account, nonce: BigInt(nonce), idx: BigInt(idx), callHash });
  const op = (idx: number, nonce: number, cached: boolean) => {
    const m = msg(idx, nonce);
    const s = C.sign(MASTER, idx, m, cached, cache);
    return { idx, nonce, tag: 'solana', callHash: hex(callHash), digest: hex(m), l0: { wots: s.l0.wots.map(hex), auth: s.l0.auth.map(hex) }, l1: s.l1 ? { wots: s.l1.wots.map(hex), auth: s.l1.auth.map(hex) } : null };
  };
  const ops = [op(0, 0, false), op(1, 1, true), op(2, 2, true)];
  const skip = { ops: [op(5, 1, true), op(1024, 2, false)] };
  const newPub = C.keygen(NEXT_MASTER);
  const recM = C.recoveryDigest({ tag: 'solana', account, recNonce: 0n, newRoot: newPub.root, newRecRoot: newPub.recRoot, newSeed: newPub.seed });
  const rec = C.signRecovery(MASTER, 0, recM, cache);
  write('cchs-c-20.json', {
    paramSet: 'CCHS-C-20', hash: 'sha256/24', n: 24, w: 256, len: 26, h: 10, recH: 8, skInfo: 'cchs/sk/c', seedInfo: 'cchs/pkseed/c',
    adrs: 'layer(1) || treeIdx(8) || type(1) || leafIdx(4) || chainIdx(1) || step(1) || pkSeed(16)',
    master: hex(MASTER.master), account: hex(account),
    root: hex(pub.root), recRoot: hex(pub.recRoot), seed: hex(pub.seed), bottomRoot0: hex(cache.get('0/0')!.root),
    ops,
    bottomRoot1: hex(cache.get('0/1')!.root),
    skip,
    recovery: { recNonce: 0, newRoot: hex(newPub.root), newRecRoot: hex(newPub.recRoot), newSeed: hex(newPub.seed), digest: hex(recM), wots: rec.wots.map(hex), auth: rec.auth.map(hex) },
  });
}

// -------------------------------------------------------------- derivation
{
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
  const passphrase = '';
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  const master = cchsMaster(mnemonic, passphrase);
  const setOf = (key: cchs.CchsKey, v: 'S' | 'K', withAccount: boolean) => {
    const c = cchs.forVariant(v);
    const cache = new Map<string, cchs.Tree>();
    const pub = c.keygen(key, cache);
    const o: Record<string, string> = {
      root: hex(pub.root), recRoot: hex(pub.recRoot), seed: hex(pub.seed), bottomRoot0: hex(c.buildTree(key, 0, 0n, cchs.H).root),
      sk_0_0_0_0: hex(cchs.sk(key, 0, 0n, 0, 0, v)),
    };
    if (withAccount) o.evmAccount = predictAccount(o.root as `0x${string}`, o.recRoot as `0x${string}`, o.seed as `0x${string}`, v);
    return o;
  };
  const vec: Record<string, unknown> & { chains: unknown[] } = {
    purpose: 'Cross-implementation derivation vector. A client that derives a different master, chain key, root, seed or address from this mnemonic is not compatible with the reference. One key tree per chain: a WOTS+ leaf of one chain is never a leaf of another.',
    mnemonic, passphrase,
    seed: hex(seed),
    masterInfo: 'aegis/cchs/master/v1',
    master: hex(master.master),
    chainInfo: 'aegis/cchs/chain/v1',
    chainTag: { evm: '0x00 || chainId as u64 big-endian', other: '0x01 || utf8(label of the digest)' },
    epochInfo: 'aegis/cchs/epoch/v1',
    skLabels: { S: 'cchs/sk', K: 'cchs/sk/k', C: 'cchs/sk/c' },
    seedLabels: { S: 'cchs/pkseed', K: 'cchs/pkseed/k', C: 'cchs/pkseed/c' },
    chains: [],
  };
  for (const chainId of [1, 8453]) {
    const key = chainKey(master, evmChainTag(chainId));
    vec.chains.push({
      kind: 'evm', chainId, tag: hex(evmChainTag(chainId)), chainKey: hex(key.master),
      sets: { 'CCHS-K-20': setOf(key, 'K', true), ...(chainId === 1 ? { 'CCHS-S-20': setOf(key, 'S', true) } : {}) },
    });
  }
  for (const label of ['ton']) {
    const key = chainKey(master, labelChainTag(label));
    vec.chains.push({
      kind: 'label', label, tag: hex(labelChainTag(label)), chainKey: hex(key.master),
      sets: { 'CCHS-S-20': setOf(key, 'S', false) },
    });
  }
  write('cchs-derivation.json', vec);
}
