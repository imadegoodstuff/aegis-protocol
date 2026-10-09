// Bounded model check of the CLIENT side of CCHS one-time-key discipline
// (CCHS.spec.md §4.3). The companion model/cchs-state.mjs checks the verifier;
// this file checks the rules the signer must follow so that no WOTS+ leaf ever
// signs two different messages, under the events the chain cannot see:
//
//   - a signed transaction is dropped, replaced or lands late
//   - a device crashes between signing and persisting its record (mutant)
//   - a device is restored from an older backup of its record
//   - several devices sign with the same master
//   - recovery (new epoch) with keys derived per epoch
//   - the same mnemonic used on several chains (--chains=2)
//
// Model: per chain, the verifier state (epoch, nextIdx, nonce, recNonce); D
// devices each holding, per chain, a persistent record signedMax[epoch] and an
// optional backup of it; a pool of broadcast-but-not-landed transactions; the
// set of every signature ever made.
//
// Invariant ONE-MESSAGE: for every leaf (tree, epoch, idx), all signatures
// ever produced carry the same message. Two different messages under one leaf
// is the WOTS+ break; everything else (landing order, drops, who registers a
// subtree) is handled by the verifier model. Which tree a chain uses is the
// point of rule R6: the reference client derives one tree per chain, so leaves
// of different chains are different leaves; the mutant `shared-tree` uses one
// tree for every chain, and the chain id in the digest then makes leaf 0 on
// chain A and leaf 0 on chain B two messages under one key.
//
// Rules under test (the reference client):
//   R1 next index = max(nextIdx, signedMax + 1), chosen before signing
//   R2 signedMax is persisted before the signature exists
//   R3 a device whose record may be stale (restored from backup) does not sign
//      under the current epoch again: it performs recovery first
//   R4 devices sharing a master partition the index space by subtree (d mod D)
//   R5 recovery messages are deterministic per (epoch, recNonce): the new roots
//      are derived from the chain key and the epoch, so a dropped recovery that
//      is re-signed is the same message
//   R6 every chain has its own key tree (derived from the master and the chain
//      tag); no tree is shared between chains
//
// Usage: node model/cchs-client.mjs             (exit 1 on any violation)
//        node model/cchs-client.mjs --chains=2   two chains, smaller bounds
//        node model/cchs-client.mjs --mutant=X  must report a violation
//        X in: record-after-sign, restore-then-wait, no-partition,
//              no-record, recovery-random-roots, shared-tree (with --chains=2)

const arg = (name, dflt) => { const a = process.argv.find((x) => x.startsWith(`--${name}=`)); return a ? a.slice(name.length + 3) : dflt; };
const MUTANT = arg('mutant', '');
const mutant = (n) => MUTANT === n;
const CHAINS = Number(arg('chains', '1'));

const H = 1;
const LEAVES = 1 << H;
const SUBTREES = 2;
const CAPACITY = LEAVES * SUBTREES;
const DEVICES = CHAINS > 1 ? 1 : 2;
const TARGETS = CHAINS > 1 ? ['A'] : ['A', 'B'];
const MAX_EPOCH = CHAINS > 1 ? 0 : 1;
const BACKUPS = CHAINS > 1 ? false : true;
const MAX_OWNER_STEPS = CHAINS > 1 ? 4 : 6;

// ---------- state ----------
const freshRecord = (epoch) => ({ signedMax: -1, recEpoch: epoch, backup: null, stale: false });
function initial() {
  return {
    chains: Array.from({ length: CHAINS }, () => ({ epoch: 0, nextIdx: 0, nonce: 0, recNonce: 0 })),
    devices: Array.from({ length: DEVICES }, () => Array.from({ length: CHAINS }, () => freshRecord(0))),
    pool: [],        // {kind:'exec', chain, epoch, idx, nonce, target, dev} | {kind:'rec', chain, epoch, recNonce, roots, dev}
    sigs: [],        // every signature ever produced (same shape as pool entries)
    steps: 0,
  };
}
const clone = (s) => ({ ...s, chains: s.chains.map((c) => ({ ...c })), devices: s.devices.map((d) => d.map((r) => ({ ...r }))), pool: s.pool.slice(), sigs: s.sigs.slice() });
const sigKey = (g) => g.kind === 'exec' ? `c${g.chain}.e${g.epoch}.${g.idx}.${g.nonce}.${g.target}` : `c${g.chain}.r${g.epoch}.${g.recNonce}.${g.roots}`;
function key(s) {
  const ch = s.chains.map((c) => `${c.epoch}/${c.nextIdx}/${c.nonce}/${c.recNonce}`).join(',');
  const dev = s.devices.map((d) => d.map((r) => `${r.signedMax}/${r.recEpoch}/${r.backup}/${r.stale ? 1 : 0}`).join('+')).join(',');
  const pool = s.pool.map(sigKey).sort().join(';');
  const sigs = [...new Set(s.sigs.map(sigKey))].sort().join(';');
  return `${ch}|${dev}|${pool}|${sigs}`;
}

// ---------- the client's rules ----------
function nextIndex(s, d, c) {
  const rec = s.devices[d][c];
  let idx = Math.max(s.chains[c].nextIdx, rec.signedMax + 1);
  if (!mutant('no-partition') && DEVICES > 1) {
    while (idx < CAPACITY && ((idx >> H) % DEVICES) !== d) idx++;   // R4: own subtrees only
  }
  return idx;
}
function maySign(s, d, c) {
  const rec = s.devices[d][c];
  if (rec.recEpoch !== s.chains[c].epoch) return false;      // keys for this epoch not yet derived
  if (rec.stale && !mutant('restore-then-wait')) return false; // R3: recover first
  if (rec.stale && mutant('restore-then-wait') && s.pool.length) return false; // the weaker rule: wait for the pool to drain
  return true;
}
// R6: which key tree signs on chain c. One tree per chain; the mutant shares one.
const treeOf = (c) => (mutant('shared-tree') ? 0 : c);

// ---------- moves ----------
function* ownerMoves(s) {
  for (let d = 0; d < DEVICES; d++) for (let c = 0; c < CHAINS; c++) {
    const ch = s.chains[c];
    const rec = s.devices[d][c];
    if (maySign(s, d, c)) {
      const idx = nextIndex(s, d, c);
      if (idx < CAPACITY) {
        for (const target of TARGETS) {
          const sig = { kind: 'exec', chain: c, epoch: ch.epoch, idx, nonce: ch.nonce, target, dev: d };
          // R2: record first. The mutants model a crash between signing and recording.
          const variants = [];
          if (mutant('no-record')) variants.push(false);
          else if (mutant('record-after-sign')) variants.push(true, false);
          else variants.push(true);
          for (const recorded of variants) {
            const n = clone(s);
            if (recorded) n.devices[d][c].signedMax = Math.max(n.devices[d][c].signedMax, idx);
            n.pool.push(sig); n.sigs.push(sig);
            yield { label: `dev${d} signs ${sigKey(sig)}${recorded ? '' : ' (record lost)'}`, next: n };
          }
        }
      }
    }
    // backup / restore of the record
    if (BACKUPS && rec.backup === null) {  // one backup per device per epoch is enough to expose a stale restore
      const n = clone(s); n.devices[d][c].backup = rec.signedMax; yield { label: `dev${d} backs up chain ${c}`, next: n };
    }
    if (rec.backup !== null && rec.backup < rec.signedMax) {
      const n = clone(s); n.devices[d][c].signedMax = rec.backup; n.devices[d][c].stale = true;
      yield { label: `dev${d} restores an old backup of chain ${c}`, next: n };
    }
    // recovery: any device with keys of the current epoch may sign it
    if (ch.epoch < MAX_EPOCH && rec.recEpoch === ch.epoch) {
      const roots = mutant('recovery-random-roots') ? `rnd${s.sigs.length}` : `det${ch.epoch + 1}`; // R5
      const sig = { kind: 'rec', chain: c, epoch: ch.epoch, recNonce: ch.recNonce, roots, dev: d };
      const n = clone(s); n.pool.push(sig); n.sigs.push(sig);
      yield { label: `dev${d} signs recovery on chain ${c}`, next: n };
    }
    // a device derives the keys of a new epoch once it sees it on chain
    if (rec.recEpoch < ch.epoch) {
      const n = clone(s); n.devices[d][c] = freshRecord(ch.epoch);
      yield { label: `dev${d} moves to epoch ${ch.epoch} on chain ${c}`, next: n };
    }
  }
}

function* networkMoves(s) {
  for (let i = 0; i < s.pool.length; i++) {
    const tx = s.pool[i];
    const ch = s.chains[tx.chain];
    // drop
    { const n = clone(s); n.pool.splice(i, 1); yield { label: `drop ${sigKey(tx)}`, next: n }; }
    // land (verifier rules; a failed landing is the same as a drop)
    if (tx.kind === 'exec' && tx.epoch === ch.epoch && tx.idx >= ch.nextIdx && tx.nonce === ch.nonce) {
      const n = clone(s); n.pool.splice(i, 1); n.chains[tx.chain].nextIdx = tx.idx + 1; n.chains[tx.chain].nonce += 1;
      yield { label: `land ${sigKey(tx)}`, next: n };
    }
    if (tx.kind === 'rec' && tx.epoch === ch.epoch && tx.recNonce === ch.recNonce) {
      const n = clone(s); n.pool.splice(i, 1);
      const nc = n.chains[tx.chain]; nc.epoch += 1; nc.recNonce += 1; nc.nextIdx = 0; nc.nonce = 0;
      n.pool = n.pool.filter((p) => p.chain !== tx.chain || p.epoch === nc.epoch); // old-epoch signatures can no longer land
      yield { label: `land recovery on chain ${tx.chain}`, next: n };
    }
  }
}

// ---------- invariant ----------
function violation(s) {
  const seen = new Map();
  for (const g of s.sigs) {
    const t = treeOf(g.chain);
    const k = g.kind === 'exec' ? `t${t}.e${g.epoch}.${g.idx}` : `t${t}.r${g.epoch}.${g.recNonce}`;
    const m = g.kind === 'exec' ? `c${g.chain}.${g.nonce}.${g.target}` : `c${g.chain}.${g.roots}`; // the chain id is part of the digest
    if (seen.has(k) && seen.get(k) !== m) return `leaf ${k} signed two messages: ${seen.get(k)} and ${m}`;
    seen.set(k, m);
  }
  return null;
}

// ---------- exploration ----------
const start = initial();
const queue = [start];
const visited = new Set([key(start)]);
let transitions = 0;
let found = null;
while (queue.length && !found) {
  const s = queue.shift();
  const moves = [...networkMoves(s)];
  if (s.steps < MAX_OWNER_STEPS) for (const m of ownerMoves(s)) { m.next.steps = s.steps + 1; moves.push(m); }
  for (const m of moves) {
    transitions++;
    const v = violation(m.next);
    if (v) { found = { v, label: m.label, state: key(s) }; break; }
    const k = key(m.next);
    if (!visited.has(k)) { visited.add(k); queue.push(m.next); }
  }
}
console.log(`${MUTANT ? `mutant ${MUTANT}: ` : ''}${CHAINS > 1 ? `${CHAINS} chains: ` : ''}states ${visited.size}, transitions ${transitions}`);
if (found) {
  console.log(`VIOLATION after "${found.label}": ${found.v}`);
  console.log(`from state ${found.state}`);
  process.exit(1);
}
if (MUTANT) { console.log('mutant was NOT caught'); process.exit(2); }
console.log('ONE-MESSAGE holds: no leaf ever signs two different messages');
