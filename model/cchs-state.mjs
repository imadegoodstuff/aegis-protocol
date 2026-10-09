// Bounded model check of the CCHS account state machine (CCHS.spec.md §5, §6, §8).
//
// The hash function is abstracted away: a signature object remembers what it was
// made over, and verification "recomputes" a root that is correct exactly when the
// object is used over the same inputs it was made for, and a fresh garbage value
// otherwise (collision- and second-preimage-resistance taken as given). What is
// left is the transition logic — index, nonce, epoch, cache, lanes — and that is
// what is explored exhaustively for small parameters.
//
// Parameters: H = 1 (two leaves per subtree), 4 subtrees per epoch split into
// 2 lanes of 2 subtrees (LANE_BITS = 1), up to one recovery, a target set of
// size 2. Every reachable state under the owner's legitimate moves interleaved
// with every adversary move is visited, and the invariants below are checked on
// every transition.
//
//   C3  no pre-recovery signature is accepted after recovery
//   C4  cachedRoot[epoch][t] is always the owner's true bottom root for (epoch, t)
//   C5  at most one acceptance per (epoch, idx); nextIdx of a lane only moves to
//       an index the owner signed in that lane; nextIdx is monotone per lane
//       within an epoch
//   NF  every acceptance carries a signature the owner made over exactly the
//       accepted (epoch, idx, lane nonce, target)
//   LI  lane independence: an acceptance in lane l does not change the verdict
//       on any signature the owner has made in another lane (what lets devices
//       sign concurrently without coordination)
//
// Usage: node model/cchs-state.mjs              (exit code 1 on any violation)
//        node model/cchs-state.mjs --mutant=X   inject a known bug; must report a violation
//        X in: no-index-check, cache-without-epoch, idx-not-in-digest, top-layer-not-bound,
//              lane-0-index-check, shared-nonce

const H = 1;
const LEAVES = 1 << H;
const SUBTREES = 4;
const CAPACITY = LEAVES * SUBTREES;
const LANE_BITS = 1;
const LANES = 1 << LANE_BITS;
const LANE_SHIFT = Math.log2(CAPACITY) - LANE_BITS;
const laneOf = (idx) => idx >> LANE_SHIFT;
const laneFirst = (l) => l << LANE_SHIFT;
const MAX_EPOCH = 1;
const TARGETS = ['A', 'B'];
const MUTANT = (process.argv.find((a) => a.startsWith('--mutant=')) || '').slice(9);
const mutant = (name) => MUTANT === name;

// ---------- abstract hash world ----------
let fresh = 0;
const garbage = () => `g${fresh++}`;
const bottomRoot = (epoch, t) => `R0(${epoch},${t})`;
const topRoot = (epoch) => `root(${epoch})`;
const recRoot = (epoch) => `rec(${epoch})`;

// A layer-0 signature object. `made` is what the owner committed to.
// `leaked` marks a signature the adversary synthesised with bottom keys of a
// subtree whose leaves are all behind the lane's nextIdx (two-message exposure, §4.3).
function makeSig(epoch, idx, nonce, target, withTop, leaked = false) {
  return { epoch, idx, nonce, target, withTop, leaked };
}

// Cache key: (epoch, treeIdx) in the protocol; the mutant drops the epoch.
const cacheKey = (epoch, t) => (mutant('cache-without-epoch') ? `${t}` : `${epoch}:${t}`);

// Lane state as the contract reads it: the lane of idx, or always lane 0 under the mutants.
const indexLane = (idx) => (mutant('lane-0-index-check') ? 0 : laneOf(idx));
const nonceLane = (idx) => (mutant('shared-nonce') ? 0 : laneOf(idx));

// Verifier, mirroring execute / executeFirst.
function verify(state, tx) {
  const { sig, idx, target } = tx;
  if (idx >= CAPACITY) return { ok: false, why: 'Exhausted' };
  if (!mutant('no-index-check') && idx < state.nextIdx[indexLane(idx)]) return { ok: false, why: 'IndexUsed' };
  const t = idx >> H;
  const nonce = state.nonce[nonceLane(idx)];
  // Recompute R0 from the signature over the digest (chainId, account, lane nonce, idx, target).
  const sameInputs = (mutant('idx-not-in-digest') || sig.idx === idx) && sig.nonce === nonce && sig.target === target;
  const r0 = sameInputs ? bottomRoot(sig.epoch, t) : garbage();
  const cached = state.cache.get(cacheKey(state.epoch, t));
  if (!tx.first) {
    if (cached === undefined) return { ok: false, why: 'MissingTopLayer' };
    if (cached !== r0) return { ok: false, why: 'BadSubtreeRoot' };
    return { ok: true, r0, registered: false };
  }
  if (cached !== undefined) {
    if (cached !== r0) return { ok: false, why: 'BadSubtreeRoot' };
    return { ok: true, r0, registered: false };
  }
  // Top layer: valid only if the owner signed R0 of this epoch with the layer-1 key
  // and R0 is the genuine one (a leaked bottom key never comes with a layer-1 key).
  const r1 = sig.withTop && (mutant('top-layer-not-bound') || (sameInputs && !sig.leaked)) ? topRoot(sig.epoch) : garbage();
  if (r1 !== state.root) return { ok: false, why: 'BadTopRoot' };
  return { ok: true, r0, registered: true };
}

function apply(state, res, idx) {
  const next = clone(state);
  if (res.registered) next.cache.set(cacheKey(state.epoch, idx >> H), res.r0);
  next.nextIdx[indexLane(idx)] = idx + 1;
  next.nonce[nonceLane(idx)] += 1;
  return next;
}

function recover(state) {
  const next = clone(state);
  next.epoch += 1;
  next.root = topRoot(next.epoch);
  next.recRoot = recRoot(next.epoch);
  next.nextIdx = Array.from({ length: LANES }, (_, l) => laneFirst(l));
  next.nonce = Array.from({ length: LANES }, () => 0);
  next.recNonce += 1;
  return next;
}

// ---------- state ----------
function initial() {
  return {
    epoch: 0, root: topRoot(0), recRoot: recRoot(0),
    nextIdx: Array.from({ length: LANES }, (_, l) => laneFirst(l)),
    nonce: Array.from({ length: LANES }, () => 0),
    recNonce: 0,
    cache: new Map(),
    seen: [],            // every signature object ever produced (owner or adversary)
    landed: [],          // accepted operations: {epoch, idx, nonce, target, sig}
    ownerSigned: [],     // {epoch, idx}
    steps: 0,
  };
}
function clone(s) {
  return { ...s, nextIdx: s.nextIdx.slice(), nonce: s.nonce.slice(), cache: new Map(s.cache), seen: s.seen.slice(), landed: s.landed.slice(), ownerSigned: s.ownerSigned.slice() };
}
function key(s) {
  const cache = [...s.cache.entries()].sort().map(([k, v]) => `${k}=${v}`).join(',');
  const seen = s.seen.map(sigKey).sort().join(';');
  const landed = s.landed.map((l) => `${l.epoch}/${l.idx}/${l.nonce}/${l.target}`).join(';');
  return `${s.epoch}|${s.nextIdx.join('.')}|${s.nonce.join('.')}|${s.recNonce}|${cache}|${seen}|${landed}`;
}
const sigKey = (g) => `${g.epoch}.${g.idx}.${g.nonce}.${g.target}.${g.withTop ? 1 : 0}.${g.leaked ? 1 : 0}`;

// ---------- invariants ----------
const violations = [];
function check(before, after, tx, res) {
  const tag = (name, msg) => violations.push({ name, msg, tx, before: key(before) });
  if (!res.ok) return;
  const { sig, idx, target } = tx;
  const lane = laneOf(idx);
  // NF: the accepted signature was made by the owner over exactly these inputs.
  if (sig.leaked) tag('NF', `leaked-key signature accepted at idx ${idx}`);
  if (sig.epoch !== before.epoch) tag('C3', `signature from epoch ${sig.epoch} accepted in epoch ${before.epoch}`);
  if (sig.idx !== idx || sig.nonce !== before.nonce[lane] || sig.target !== target) tag('NF', 'accepted over inputs the owner did not sign');
  // C5: one acceptance per (epoch, idx); the lane's nextIdx moves only to owner-signed idx, and only forward.
  if (before.landed.some((l) => l.epoch === before.epoch && l.idx === idx)) tag('C5', `second acceptance at (${before.epoch}, ${idx})`);
  if (after.nextIdx[lane] <= before.nextIdx[lane]) tag('C5', `nextIdx of lane ${lane} did not advance`);
  for (let l = 0; l < LANES; l++) if (l !== lane && after.nextIdx[l] !== before.nextIdx[l]) tag('C5', `acceptance in lane ${lane} moved nextIdx of lane ${l}`);
  if (!before.ownerSigned.some((o) => o.epoch === before.epoch && o.idx === idx)) tag('C5', `nextIdx moved to ${idx + 1} without an owner signature at ${idx}`);
  // C4: cache entries are genuine bottom roots of the current epoch.
  for (const [k, v] of after.cache) {
    const t = Number(k.includes(':') ? k.split(':')[1] : k);
    const e = k.includes(':') ? Number(k.split(':')[0]) : after.epoch;
    if (e !== after.epoch) continue; // stale epochs are unreachable through cacheKey
    if (v !== bottomRoot(after.epoch, t)) tag('C4', `cache[${k}] = ${v} in epoch ${after.epoch}`);
  }
  // LI: every owner signature in another lane that the verifier would accept
  // before this acceptance is still accepted after it (and vice versa).
  for (const g of before.seen) {
    if (g.leaked || g.epoch !== before.epoch || laneOf(g.idx) === lane) continue;
    for (const first of [false, true]) {
      const probe = { sig: g, idx: g.idx, target: g.target, first };
      const b = verify(before, probe).ok, a = verify(after, probe).ok;
      if (b !== a) tag('LI', `acceptance at idx ${idx} (lane ${lane}) changed the verdict on ${sigKey(g)} (lane ${laneOf(g.idx)}) from ${b} to ${a}`);
    }
  }
}

// ---------- moves ----------
function* ownerMoves(s) {
  // Sign at any idx >= nextIdx of its lane (the client rule allows skipping),
  // with or without the top layer, for any target. Signing does not change
  // chain state; the signature joins the pool and may be submitted by anyone,
  // in any order. The owner always signs for TARGETS[0]; the adversary tries
  // every other target at submission time, which covers tampering without
  // multiplying owner moves. The owner signs in a lane with that lane's nonce,
  // which is what a device that reads only its own lane does.
  const target = TARGETS[0];
  for (let idx = 0; idx < CAPACITY; idx++) {
    const lane = laneOf(idx);
    if (idx < s.nextIdx[lane]) continue;
    for (const withTop of [false, true]) {
      const sig = makeSig(s.epoch, idx, s.nonce[lane], target, withTop);
      if (s.seen.some((g) => sigKey(g) === sigKey(sig))) continue;
      const next = clone(s);
      next.seen.push(sig);
      next.ownerSigned.push({ epoch: s.epoch, idx });
      yield { label: `owner signs ${sigKey(sig)}`, next };
    }
  }
  if (s.epoch < MAX_EPOCH) yield { label: 'owner recovers', next: recover(s) };
}

function* adversaryMoves(s) {
  // 1. Submit any seen signature under any (idx, target, first) choice.
  for (const sig of s.seen) {
    for (let idx = 0; idx < CAPACITY; idx++) {
      for (const target of TARGETS) {
        for (const first of [false, true]) {
          yield { sig, idx, target, first };
        }
      }
    }
  }
  // 2. Bottom keys of fully-abandoned subtrees are assumed exposed: forge any
  //    message there, for the current epoch, with or without a (fake) top layer.
  for (let t = 0; t < SUBTREES; t++) {
    const lastLeaf = (t + 1) * LEAVES - 1;
    if (lastLeaf >= s.nextIdx[laneOf(lastLeaf)]) continue;
    for (let idx = t * LEAVES; idx <= lastLeaf; idx++) {
      for (const target of TARGETS) {
        for (const first of [false, true]) {
          yield { sig: makeSig(s.epoch, idx, s.nonce[laneOf(idx)], target, first, true), idx, target, first, forged: true };
        }
      }
    }
  }
}

// ---------- exploration ----------
const MAX_STEPS = 5; // depth bound on the number of owner signatures/recoveries
const start = initial();
const queue = [start];
const visited = new Set([key(start)]);
let transitions = 0, accepted = 0, rejected = 0;

while (queue.length) {
  const s = queue.shift();
  // Adversary: every submission against this state.
  for (const tx of adversaryMoves(s)) {
    transitions++;
    const res = verify(s, tx);
    if (!res.ok) { rejected++; continue; }
    accepted++;
    const after = apply(s, res, tx.idx);
    after.landed.push({ epoch: s.epoch, idx: tx.idx, nonce: s.nonce[laneOf(tx.idx)], target: tx.target, sig: tx.sig });
    if (tx.forged) after.seen.push(tx.sig);
    check(s, after, tx, res);
    if (violations.length && MUTANT) { queue.length = 0; break; } // a mutant only has to be caught once
    const k = key(after);
    if (!visited.has(k)) { visited.add(k); queue.push(after); }
  }
  // Owner: produce more signatures or recover.
  if (s.steps >= MAX_STEPS) continue;
  for (const m of ownerMoves(s)) {
    m.next.steps = s.steps + 1;
    const k = key(m.next);
    if (!visited.has(k)) { visited.add(k); queue.push(m.next); }
  }
}

console.log(`${MUTANT ? `mutant ${MUTANT}: ` : ''}states ${visited.size}, submissions ${transitions} (accepted ${accepted}, rejected ${rejected})`);
if (violations.length) {
  console.log(`VIOLATIONS: ${violations.length}`);
  for (const v of violations.slice(0, 5)) console.log(' ', v.name, v.msg, JSON.stringify({ idx: v.tx.idx, target: v.tx.target, first: v.tx.first, sig: sigKey(v.tx.sig) }), 'state', v.before);
  process.exit(1);
}
if (MUTANT) { console.log('mutant was NOT caught'); process.exit(2); }
console.log('invariants C3 C4 C5 NF LI hold on every transition');
