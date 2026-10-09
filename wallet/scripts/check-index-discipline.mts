// Unit checks for the client-side one-time-key discipline in cchsAccount.ts,
// against an in-memory localStorage: write-ahead record, abandoned leaves,
// missing record, epoch scoping, recovery record, per-epoch key derivation.
// Run with `npm run index-discipline`; CI runs it with the other vector checks.

const store = new Map<string, string>();
(globalThis as any).localStorage = {
  getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
  setItem: (k: string, v: string) => { store.set(k, String(v)); },
  removeItem: (k: string) => { store.delete(k); },
  clear: () => store.clear(),
};

const { nextSigningIndex, markIndexSigned, highestSignedIndex, recordMissing, highestRecoverySigned, markRecoverySigned, epochKey, chainKey, evmChainTag, labelChainTag, laneOf, laneFirst, deviceLane, setDeviceLane, LANES } = await import('../src/aegis/cchsAccount.ts');
const { toHex, cchsK, sk } = await import('../src/aegis/cchs.ts');

let failures = 0;
const ok = (cond: boolean, what: string) => { if (!cond) failures++; console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`); };
const A = '0x000000000000000000000000000000000000cc45' as const;
const B = '0x000000000000000000000000000000000000cc46' as const;

// fresh account: no record, nextIdx 0 -> sign at 0, record 0
ok(!recordMissing(1, A, 0, 0n), 'fresh account (nextIdx 0) needs no record');
ok(nextSigningIndex(1, A, 0, 0n) === 0, 'first index is 0');
markIndexSigned(1, A, 0, 0);
ok(highestSignedIndex(1, A, 0) === 0, 'record written before signing');

// the transaction was dropped: chain still says 0, device moves on to 1 (leaf 0 abandoned)
ok(nextSigningIndex(1, A, 0, 0n) === 1, 'dropped transaction: leaf 0 is never signed again');
markIndexSigned(1, A, 0, 1);
// chain caught up to 5 (another leaf landed from a jump): device follows the chain
ok(nextSigningIndex(1, A, 0, 5n) === 5, 'device follows the chain when it is ahead');
// record never moves backwards
markIndexSigned(1, A, 0, 3);
markIndexSigned(1, A, 0, 2);
ok(highestSignedIndex(1, A, 0) === 3, 'record is monotonic (3 then 2 leaves 3)');

// records are scoped by chain, account and epoch
ok(highestSignedIndex(5, A, 0) === null, 'other chain: no record');
ok(highestSignedIndex(1, B, 0) === null, 'other account: no record');
ok(highestSignedIndex(1, A, 1) === null, 'other epoch: no record');
ok(recordMissing(1, B, 0, 7n), 'used account without a record is flagged');
ok(!recordMissing(1, B, 0, 0n), 'unused account without a record is not flagged');

// lost record while the account is in use -> must rotate; after rotation a fresh record exists for epoch 1
store.clear();
ok(recordMissing(1, A, 0, 2n), 'cleared storage with nextIdx 2: signing in epoch 0 is refused');
ok(highestRecoverySigned(1, A) === -1, 'no recovery signed yet');
markRecoverySigned(1, A, 0);
ok(highestRecoverySigned(1, A) === 0, 'recovery leaf 0 recorded before signing');
markIndexSigned(1, A, 1, -1);
ok(!recordMissing(1, A, 1, 0n) && nextSigningIndex(1, A, 1, 0n) === 0, 'epoch 1 starts with a fresh record at index 0');

// lanes: a second device owns lane 3; its record is separate, its first index is the lane's first leaf,
// and a lane that has been used without a record on this device is refused like an account was.
store.clear();
ok(laneOf(0) === 0 && laneOf(65_535) === 0 && laneOf(65_536) === 1 && laneOf((1 << 20) - 1) === LANES - 1, 'lane = top four bits of the index');
ok(laneFirst(3) === 3 * 65_536, 'lane 3 starts at leaf 196 608');
ok(deviceLane() === 0, 'a device defaults to lane 0');
setDeviceLane(3);
ok(deviceLane() === 3, 'the device lane is persisted');
let threw = false; try { setDeviceLane(16); } catch { threw = true; }
ok(threw, 'lane 16 does not exist');
ok(!recordMissing(1, A, 0, BigInt(laneFirst(3)), 3), 'fresh lane 3 (nextIdx at its first leaf) needs no record');
ok(nextSigningIndex(1, A, 0, BigInt(laneFirst(3)), 3) === laneFirst(3), 'first index in lane 3 is its first leaf, even though lane 0 has records');
ok(nextSigningIndex(1, A, 0, 0n, 3) === laneFirst(3), 'a chain value below the lane (misread) never pulls the index out of the lane');
markIndexSigned(1, A, 0, laneFirst(3), 3);
ok(highestSignedIndex(1, A, 0, 3) === laneFirst(3) && highestSignedIndex(1, A, 0, 0) === null, 'lane records are separate (lane 0 untouched)');
ok(nextSigningIndex(1, A, 0, BigInt(laneFirst(3)), 3) === laneFirst(3) + 1, 'dropped lane-3 transaction: its leaf is abandoned');
ok(recordMissing(1, A, 0, BigInt(laneFirst(2) + 5), 2), 'lane 2 used on chain, no record here: refused');
threw = false; try { nextSigningIndex(1, A, 0, BigInt(laneFirst(4)), 3); } catch { threw = true; }
ok(threw, 'a lane cannot sign past its last leaf');
setDeviceLane(0);

// per-epoch keys: epoch 0 is the master; later epochs are distinct and deterministic
const master = { master: new Uint8Array(32).fill(7) };
ok(epochKey(master, 0) === master, 'epoch 0 key is the master itself (vectors unchanged)');
const e1 = epochKey(master, 1), e1b = epochKey(master, 1), e2 = epochKey(master, 2);
ok(toHex(e1.master) === toHex(e1b.master), 'epoch key derivation is deterministic');
ok(toHex(e1.master) !== toHex(master.master) && toHex(e1.master) !== toHex(e2.master), 'epoch keys are pairwise distinct');
ok(toHex(sk(master, 0, 0n, 0, 0, 'K')) !== toHex(sk(e1, 0, 0n, 0, 0, 'K')), 'WOTS+ secret values differ across epochs');
console.log(`epoch 1 master for 0x07..07: ${toHex(e1.master)}`);
console.log(`epoch 1 K-20 root for 0x07..07: ${toHex(cchsK.keygen(e1).root)}`);

// per-chain keys: one tree per chain, so a leaf of chain A is never a leaf of chain B
const t1 = evmChainTag(1), t8453 = evmChainTag(8453), tTon = labelChainTag('ton');
ok(toHex(t1) === '0x000000000000000001' && toHex(t8453) === '0x000000000000002105', 'EVM chain tag is 0x00 || chainId u64 BE');
ok(toHex(tTon) === '0x01746f6e', 'label chain tag is 0x01 || utf8(label)');
const c1 = chainKey(master, t1), c1b = chainKey(master, t1), c8453 = chainKey(master, t8453), cTon = chainKey(master, tTon);
ok(toHex(c1.master) === toHex(c1b.master), 'chain key derivation is deterministic');
ok(new Set([toHex(master.master), toHex(c1.master), toHex(c8453.master), toHex(cTon.master)]).size === 4, 'master and chain keys are pairwise distinct');
ok(toHex(sk(c1, 0, 0n, 0, 0, 'K')) !== toHex(sk(c8453, 0, 0n, 0, 0, 'K')), 'WOTS+ secret values differ across chains');
ok(toHex(epochKey(c1, 1).master) !== toHex(epochKey(c8453, 1).master), 'epoch keys of different chains differ');

// End to end, the way the wallet signs: the same mnemonic, leaf 0 on chain 1 and
// leaf 0 on chain 8453, each over its own chain's digest. Derivation, index
// choice and the signature itself are exercised together; the two leaves must
// be different one-time keys, and neither chain's root must accept the other's
// signature.
{
  const treesA = new Map(), treesB = new Map();
  const pubA = cchsK.keygen(c1, treesA), pubB = cchsK.keygen(c8453, treesB);
  ok(toHex(pubA.root) !== toHex(pubB.root), 'chains 1 and 8453 have different roots (different accounts)');
  const account = A;
  const acct = Uint8Array.from(Buffer.from(account.slice(2), 'hex'));
  const target = new Uint8Array(20).fill(0xab);
  const dataHash = new Uint8Array(32);
  const digest = (chainId: bigint) => cchsK.executeDigest({ chainId, account: acct, nonce: 0n, idx: 0n, target, value: 1n, dataHash });
  const mA = digest(1n), mB = digest(8453n);
  ok(toHex(mA) !== toHex(mB), 'the digests differ by chain id (replay protection)');
  const idxA = nextSigningIndex(1, B, 0, 0n), idxB = nextSigningIndex(8453, B, 0, 0n);
  ok(idxA === 0 && idxB === 0, 'both chains start at leaf 0: the index spaces are independent');
  markIndexSigned(1, B, 0, idxA); markIndexSigned(8453, B, 0, idxB);
  const sA = cchsK.sign(c1, idxA, mA, false, treesA), sB = cchsK.sign(c8453, idxB, mB, false, treesB);
  const shared = sA.l0.wots.filter((x, i) => toHex(x) === toHex(sB.l0.wots[i])).length;
  ok(shared === 0, `leaf 0 of chain 1 and leaf 0 of chain 8453 share no chain value (${shared} of ${sA.l0.wots.length} equal)`);
  ok(toHex(sk(c1, 0, 0n, 0, 0, 'K')) !== toHex(sk(c8453, 0, 0n, 0, 0, 'K')), 'their WOTS+ secret keys differ: two one-time keys, one message each');
  const accepts = (pub: { root: Uint8Array; recRoot: Uint8Array; seed: Uint8Array }, m: Uint8Array, s: any) => { try { cchsK.verify(pub, 0, m, s); return true; } catch { return false; } };
  ok(accepts(pubA, mA, sA) && accepts(pubB, mB, sB), 'each signature verifies under its own chain root');
  ok(!accepts(pubA, mB, sB) && !accepts(pubB, mA, sA), 'neither root accepts the other chain\'s signature');
  ok(toHex(pubA.seed) !== toHex(pubB.seed), 'the two trees carry different public seeds: no hash position is shared between them');
}

if (failures) { console.log(`${failures} check(s) failed`); process.exit(1); }
console.log('index discipline checks passed');
