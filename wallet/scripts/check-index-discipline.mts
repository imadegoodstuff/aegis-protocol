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

const { nextSigningIndex, markIndexSigned, highestSignedIndex, recordMissing, highestRecoverySigned, markRecoverySigned, epochKey } = await import('../src/aegis/cchsAccount.ts');
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

// per-epoch keys: epoch 0 is the master; later epochs are distinct and deterministic
const master = { master: new Uint8Array(32).fill(7) };
ok(epochKey(master, 0) === master, 'epoch 0 key is the master itself (vectors unchanged)');
const e1 = epochKey(master, 1), e1b = epochKey(master, 1), e2 = epochKey(master, 2);
ok(toHex(e1.master) === toHex(e1b.master), 'epoch key derivation is deterministic');
ok(toHex(e1.master) !== toHex(master.master) && toHex(e1.master) !== toHex(e2.master), 'epoch keys are pairwise distinct');
ok(toHex(sk(master, 0, 0n, 0, 0, 'K')) !== toHex(sk(e1, 0, 0n, 0, 0, 'K')), 'WOTS+ secret values differ across epochs');
console.log(`epoch 1 master for 0x07..07: ${toHex(e1.master)}`);
console.log(`epoch 1 K-20 root for 0x07..07: ${toHex(cchsK.keygen(e1).root)}`);

if (failures) { console.log(`${failures} check(s) failed`); process.exit(1); }
console.log('index discipline checks passed');
