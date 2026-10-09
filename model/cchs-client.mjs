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
//
// Model: chain state (epoch, nextIdx, nonce); D devices each holding a
// persistent record signedMax[epoch] and an optional backup of it; a pool of
// broadcast-but-not-landed transactions; the set of every signature ever made.
//
// Invariant ONE-MESSAGE: for every (epoch, idx), all signatures ever produced
// carry the same (nonce, target). Two different messages under one leaf is the
// WOTS+ break; everything else (landing order, drops, who registers a subtree)
// is handled by the verifier model.
//
// Rules under test (the reference client):
//   R1 next index = max(nextIdx, signedMax + 1), chosen before signing
//   R2 signedMax is persisted before the signature exists
//   R3 a device whose record may be stale (restored from backup) does not sign
//      under the current epoch again: it performs recovery first
//   R4 devices sharing a master partition the index space by subtree (d mod D)
//   R5 recovery messages are deterministic per (epoch, recNonce): the new roots
//      are derived from the master and the epoch, so a dropped recovery that
//      is re-signed is the same message
//
// Usage: node model/cchs-client.mjs             (exit 1 on any violation)
//        node model/cchs-client.mjs --mutant=X  must report a violation
//        X in: record-after-sign, restore-then-wait, no-partition,
//              no-record, recovery-random-roots

const H = 1;
const LEAVES = 1 << H;
const SUBTREES = 2;
const CAPACITY = LEAVES * SUBTREES;
const DEVICES = 2;
const TARGETS = ['A', 'B'];
const MAX_EPOCH = 1;
const MAX_OWNER_STEPS = 6;
const MUTANT = (process.argv.find((a) => a.startsWith('--mutant=')) || '').slice(9);
const mutant = (n) => MUTANT === n;

// ---------- state ----------
function initial() {
  return {
    epoch: 0, nextIdx: 0, nonce: 0, recNonce: 0,
    devices: Array.from({ length: DEVICES }, () => ({ signedMax: -1, recEpoch: 0, backup: null, stale: false })),
    pool: [],        // {kind:'exec', epoch, idx, nonce, target, dev} | {kind:'rec', epoch, recNonce, roots, dev}
    sigs: [],        // every signature ever produced (same shape as pool entries)
    steps: 0,
  };
}
const clone = (s) => ({ ...s, devices: s.devices.map((d) => ({ ...d })), pool: s.pool.slice(), sigs: s.sigs.slice() });
const sigKey = (g) => g.kind === 'exec' ? `e${g.epoch}.${g.idx}.${g.nonce}.${g.target}` : `r${g.epoch}.${g.recNonce}.${g.roots}`;
function key(s) {
  const dev = s.devices.map((d) => `${d.signedMax}/${d.recEpoch}/${d.backup}/${d.stale ? 1 : 0}`).join(',');
  const pool = s.pool.map(sigKey).sort().join(';');
  const sigs = [...new Set(s.sigs.map(sigKey))].sort().join(';');
  return `${s.epoch}|${s.nextIdx}|${s.nonce}|${s.recNonce}|${dev}|${pool}|${sigs}`;
}

// ---------- the client's rules ----------
function nextIndex(s, d) {
  const dev = s.devices[d];
  let idx = Math.max(s.nextIdx, dev.signedMax + 1);
  if (!mutant('no-partition') && DEVICES > 1) {
    while (idx < CAPACITY && ((idx >> H) % DEVICES) !== d) idx++;   // R4: own subtrees only
  }
  return idx;
}
function maySign(s, d) {
  const dev = s.devices[d];
  if (dev.recEpoch !== s.epoch) return false;             // keys for this epoch not yet derived
  if (dev.stale && !mutant('restore-then-wait')) return false; // R3: recover first
  if (dev.stale && mutant('restore-then-wait') && s.pool.length) return false; // the weaker rule: wait for the pool to drain
  return true;
}

// ---------- moves ----------
function* ownerMoves(s) {
  for (let d = 0; d < DEVICES; d++) {
    const dev = s.devices[d];
    if (maySign(s, d)) {
      const idx = nextIndex(s, d);
      if (idx < CAPACITY) {
        for (const target of TARGETS) {
          const sig = { kind: 'exec', epoch: s.epoch, idx, nonce: s.nonce, target, dev: d };
          // R2: record first. The mutants model a crash between signing and recording.
          const variants = [];
          if (mutant('no-record')) variants.push(false);
          else if (mutant('record-after-sign')) variants.push(true, false);
          else variants.push(true);
          for (const recorded of variants) {
            const n = clone(s);
            if (recorded) n.devices[d].signedMax = Math.max(n.devices[d].signedMax, idx);
            n.pool.push(sig); n.sigs.push(sig);
            yield { label: `dev${d} signs ${sigKey(sig)}${recorded ? '' : ' (record lost)'}`, next: n };
          }
        }
      }
    }
    // backup / restore of the record
    if (dev.backup === null) {  // one backup per device per epoch is enough to expose a stale restore
      const n = clone(s); n.devices[d].backup = dev.signedMax; yield { label: `dev${d} backs up`, next: n };
    }
    if (dev.backup !== null && dev.backup < dev.signedMax) {
      const n = clone(s); n.devices[d].signedMax = dev.backup; n.devices[d].stale = true;
      yield { label: `dev${d} restores an old backup`, next: n };
    }
    // recovery: any device with keys of the current epoch may sign it
    if (s.epoch < MAX_EPOCH && dev.recEpoch === s.epoch) {
      const roots = mutant('recovery-random-roots') ? `rnd${s.sigs.length}` : `det${s.epoch + 1}`; // R5
      const sig = { kind: 'rec', epoch: s.epoch, recNonce: s.recNonce, roots, dev: d };
      const n = clone(s); n.pool.push(sig); n.sigs.push(sig);
      yield { label: `dev${d} signs recovery`, next: n };
    }
    // a device derives the keys of a new epoch once it sees it on chain
    if (dev.recEpoch < s.epoch) {
      const n = clone(s); n.devices[d] = { signedMax: -1, recEpoch: s.epoch, backup: null, stale: false };
      yield { label: `dev${d} moves to epoch ${s.epoch}`, next: n };
    }
  }
}

function* networkMoves(s) {
  for (let i = 0; i < s.pool.length; i++) {
    const tx = s.pool[i];
    // drop
    { const n = clone(s); n.pool.splice(i, 1); yield { label: `drop ${sigKey(tx)}`, next: n }; }
    // land (verifier rules; a failed landing is the same as a drop)
    if (tx.kind === 'exec' && tx.epoch === s.epoch && tx.idx >= s.nextIdx && tx.nonce === s.nonce) {
      const n = clone(s); n.pool.splice(i, 1); n.nextIdx = tx.idx + 1; n.nonce += 1;
      yield { label: `land ${sigKey(tx)}`, next: n };
    }
    if (tx.kind === 'rec' && tx.epoch === s.epoch && tx.recNonce === s.recNonce) {
      const n = clone(s); n.pool.splice(i, 1); n.epoch += 1; n.recNonce += 1; n.nextIdx = 0; n.nonce = 0;
      n.pool = n.pool.filter((p) => p.epoch === n.epoch); // old-epoch signatures can no longer land
      yield { label: 'land recovery', next: n };
    }
  }
}

// ---------- invariant ----------
function violation(s) {
  const seen = new Map();
  for (const g of s.sigs) {
    const k = g.kind === 'exec' ? `e${g.epoch}.${g.idx}` : `r${g.epoch}.${g.recNonce}`;
    const m = g.kind === 'exec' ? `${g.nonce}.${g.target}` : g.roots;
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
console.log(`${MUTANT ? `mutant ${MUTANT}: ` : ''}states ${visited.size}, transitions ${transitions}`);
if (found) {
  console.log(`VIOLATION after "${found.label}": ${found.v}`);
  console.log(`from state ${found.state}`);
  process.exit(1);
}
if (MUTANT) { console.log('mutant was NOT caught'); process.exit(2); }
console.log('ONE-MESSAGE holds: no leaf ever signs two different messages');
