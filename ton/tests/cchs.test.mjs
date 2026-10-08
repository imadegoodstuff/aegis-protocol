// Fixture-driven tests for contracts/aegis_account.fc in the TON sandbox.
//
// Part 1 feeds the shared vectors (evm/test/fixtures/cchs-s-20.json) to the
// pure `compute_layer_root` get method: bottom layer, top layer and recovery.
// Part 2 derives keys from the fixture master seed, signs TON-specific digests
// and drives execute (new subtree, cached subtree, replay) and recover.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, hkdfSync } from 'node:crypto';
import { Blockchain } from '@ton/sandbox';
import { Cell, beginCell, toNano, contractAddress, internal, storeMessageRelaxed, TupleReader } from '@ton/core';
import { compile } from '../scripts/compile.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(resolve(here, '../../evm/test/fixtures/cchs-s-20.json'), 'utf8'));

const hex = (h) => Buffer.from(h.slice(2), 'hex');
const big = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
const sha = (...p) => createHash('sha256').update(Buffer.concat(p)).digest();
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };

// ------------------------------------------------------------ CCHS client
// Mirrors wallet/src/aegis/cchs.ts (keygen, sign, auth path).
const W = 16, LEN = 67, H = 10, REC_H = 8;
const master = hex(fx.master);

function adrs(layer, treeIdx, typ, leafIdx, chainIdx, step) {
  return Buffer.concat([Buffer.from([layer]), u64(treeIdx), Buffer.from([typ]), u32(leafIdx), Buffer.from([chainIdx, step]), Buffer.alloc(16)]);
}
function digits(m) {
  const d = []; let csum = 0;
  for (let i = 0; i < 32; i++) { const hi = m[i] >> 4, lo = m[i] & 15; d.push(hi, lo); csum += (W - 1 - hi) + (W - 1 - lo); }
  d.push((csum >> 8) & 15, (csum >> 4) & 15, csum & 15);
  return d;
}
function sk(layer, treeIdx, leafIdx, chainIdx) {
  const info = Buffer.concat([Buffer.from('cchs/sk'), Buffer.from([layer]), u64(treeIdx), u32(leafIdx), Buffer.from([chainIdx])]);
  return Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), info, 32));
}
function wotsLeaf(layer, treeIdx, leafIdx) {
  const parts = [adrs(layer, treeIdx, 1, leafIdx, 0, 0)];
  for (let c = 0; c < LEN; c++) {
    let x = sk(layer, treeIdx, leafIdx, c);
    for (let s = 0; s < W - 1; s++) x = sha(adrs(layer, treeIdx, 0, leafIdx, c, s), x);
    parts.push(x);
  }
  return sha(...parts);
}
function buildTree(layer, treeIdx, height) {
  const levels = [Array.from({ length: 1 << height }, (_, j) => wotsLeaf(layer, treeIdx, j))];
  for (let k = 0; k < height; k++) {
    const prev = levels[k], next = [];
    for (let i = 0; i < prev.length / 2; i++) next.push(sha(adrs(layer, treeIdx, 2, i, k, 0), prev[2 * i], prev[2 * i + 1]));
    levels.push(next);
  }
  return { height, levels, root: levels[height][0] };
}
function authPath(t, leafIdx) {
  const p = []; let pos = leafIdx;
  for (let k = 0; k < t.height; k++) { p.push(t.levels[k][pos ^ 1]); pos >>= 1; }
  return p;
}
function wotsSign(layer, treeIdx, leafIdx, m) {
  const d = digits(m), out = [];
  for (let c = 0; c < LEN; c++) {
    let x = sk(layer, treeIdx, leafIdx, c);
    for (let s = 0; s < d[c]; s++) x = sha(adrs(layer, treeIdx, 0, leafIdx, c, s), x);
    out.push(x);
  }
  return out;
}

// ------------------------------------------------------------ cell layout
const OP_EXECUTE = 0x41455845;
const OP_RECOVER = 0x41455243;

/** 256-bit values, three per cell, each cell referencing the next. */
function valueStream(values) {
  let next = null;
  for (let i = values.length; i > 0; i -= 3) {
    const b = beginCell();
    for (let j = Math.max(0, i - 3); j < i; j++) b.storeUint(big(values[j]), 256);
    if (next) b.storeRef(next);
    next = b.endCell();
  }
  return next;
}
const layerStream = (wots, auth) => valueStream([...wots, ...auth]);

// ------------------------------------------------------------ harness
async function setup(root, recRoot) {
  const r = await compile();
  const code = Cell.fromBoc(Buffer.from(r.codeBoc, 'base64'))[0];
  const data = beginCell()
    .storeUint(big(root), 256).storeUint(big(recRoot), 256)
    .storeUint(0, 64).storeUint(0, 64).storeUint(0, 64).storeUint(0, 64)
    .storeBit(0)
    .endCell();
  const init = { code, data };
  const address = contractAddress(0, init);
  const bc = await Blockchain.create();
  const relayer = await bc.treasury('relayer');
  const target = await bc.treasury('target');
  await relayer.send({ to: address, value: toNano('10'), init, body: beginCell().endCell(), bounce: false });

  const get = async (name, args = []) => {
    const g = await bc.runGetMethod(address, name, args);
    assert.equal(g.exitCode, 0, `${name} exit code`);
    return { gas: g.gasUsed, rd: new TupleReader(g.stack) };
  };
  const state = async () => {
    const { rd } = await get('get_account_state');
    return { root: rd.readBigNumber(), recRoot: rd.readBigNumber(), epoch: rd.readBigNumber(), nextIdx: rd.readBigNumber(), nonce: rd.readBigNumber(), recNonce: rd.readBigNumber() };
  };
  const send = async (body) => {
    const r = await relayer.send({ to: address, value: toNano('1'), body, bounce: true });
    const tx = r.transactions.find((t) => t.inMessage?.info?.dest?.equals?.(address));
    return { exit: tx.description.computePhase.exitCode, gas: tx.description.computePhase.gasUsed };
  };
  return { bc, address, relayer, target, get, state, send };
}

const int = (value) => ({ type: 'int', value });
const cell = (c) => ({ type: 'cell', cell: c });

// ------------------------------------------------------------ part 1
test('compute_layer_root reproduces fixture roots', async () => {
  const h = await setup(hex(fx.root), hex(fx.recRoot));
  const op1 = fx.ops[1], op0 = fx.ops[0], rec = fx.recovery;

  let g = await h.get('compute_layer_root', [int(0n), int(0n), int(1n), int(BigInt(H)), int(big(hex(op1.digest))), cell(layerStream(op1.l0.wots.map(hex), op1.l0.auth.map(hex)))]);
  assert.equal(g.rd.readBigNumber(), big(hex(fx.bottomRoot0)), 'bottom layer (ops[1])');

  g = await h.get('compute_layer_root', [int(1n), int(0n), int(0n), int(BigInt(H)), int(big(hex(fx.bottomRoot0))), cell(layerStream(op0.l1.wots.map(hex), op0.l1.auth.map(hex)))]);
  assert.equal(g.rd.readBigNumber(), big(hex(fx.root)), 'top layer (ops[0])');

  g = await h.get('compute_layer_root', [int(0xffn), int(0n), int(0n), int(BigInt(REC_H)), int(big(hex(rec.digest))), cell(layerStream(rec.wots.map(hex), rec.auth.map(hex)))]);
  assert.equal(g.rd.readBigNumber(), big(hex(fx.recRoot)), 'recovery tree');

  // A tampered chain value changes the root.
  const tampered = op1.l0.wots.map(hex); tampered[0] = sha(tampered[0]);
  g = await h.get('compute_layer_root', [int(0n), int(0n), int(1n), int(BigInt(H)), int(big(hex(op1.digest))), cell(layerStream(tampered, op1.l0.auth.map(hex)))]);
  assert.notEqual(g.rd.readBigNumber(), big(hex(fx.bottomRoot0)));
});

// ------------------------------------------------------------ part 2
test('execute and recover with client-generated signatures', async () => {
  const top = buildTree(1, 0, H);
  const rec = buildTree(0xff, 0, REC_H);
  const bottom0 = buildTree(0, 0, H);
  assert.ok(top.root.equals(hex(fx.root)), 'keygen reproduces fixture root');
  assert.ok(rec.root.equals(hex(fx.recRoot)), 'keygen reproduces fixture recRoot');
  assert.ok(bottom0.root.equals(hex(fx.bottomRoot0)));

  const h = await setup(top.root, rec.root);
  const action = (amount) => beginCell().storeUint(1, 8)
    .storeRef(beginCell().store(storeMessageRelaxed(internal({ to: h.target.address, value: toNano(amount), bounce: false }))).endCell())
    .endCell();
  const execDigest = (nonce, idx, act) => sha(Buffer.from('AEGIS_CCHS_V1'), Buffer.from('ton'), h.address.hash, u64(nonce), u64(idx), act.hash());
  const execBody = (idx, nonce, act, withL1) => {
    const m = execDigest(nonce, idx, act);
    const treeIdx = idx >> H, leafIdx = idx & ((1 << H) - 1);
    const b = beginCell().storeUint(OP_EXECUTE, 32).storeUint(0, 64).storeBit(withL1 ? 1 : 0)
      .storeRef(layerStream(wotsSign(0, treeIdx, leafIdx, m), authPath(bottom0, leafIdx)))
      .storeRef(act);
    if (withL1) b.storeRef(layerStream(wotsSign(1, 0, treeIdx, bottom0.root), authPath(top, treeIdx)));
    return b.endCell();
  };

  // get_next_digest agrees with the client.
  const a0 = action('0.5');
  const { rd } = await h.get('get_next_digest', [int(big(a0.hash()))]);
  assert.equal(rd.readBigNumber(), big(execDigest(0, 0, a0)));
  assert.equal((await h.get('needs_top_layer')).rd.readBigNumber(), -1n);

  // Cached path without the top layer must be refused on a fresh subtree.
  let r = await h.send(execBody(0, 0, a0, false));
  assert.equal(r.exit, 202, 'missing top layer');

  // First signature in subtree 0: both layers, cache written, message sent.
  let before = await h.target.getBalance();
  r = await h.send(execBody(0, 0, a0, true));
  assert.equal(r.exit, 0);
  assert.ok((await h.target.getBalance()) - before > toNano('0.49'));
  let s = await h.state();
  assert.deepEqual([s.nextIdx, s.nonce, s.epoch], [1n, 1n, 0n]);
  assert.equal((await h.get('get_cached_root', [int(0n), int(0n)])).rd.readBigNumber(), big(bottom0.root));
  assert.equal((await h.get('needs_top_layer')).rd.readBigNumber(), 0n);
  console.log(`gas: first-in-subtree execute ${r.gas}`);

  // Second signature: cached path.
  before = await h.target.getBalance();
  r = await h.send(execBody(1, 1, action('0.25'), false));
  assert.equal(r.exit, 0);
  assert.ok((await h.target.getBalance()) - before > toNano('0.24'));
  console.log(`gas: cached execute ${r.gas}`);

  // Replay of the idx-1 signature (chain is now at idx 2, nonce 2) must fail.
  r = await h.send(execBody(1, 1, action('0.25'), false));
  assert.equal(r.exit, 201, 'stale signature rejected');

  // Recovery rotates roots, resets the index space and bumps the epoch.
  s = await h.state();
  const newRoot = hex(fx.recovery.newRoot), newRecRoot = hex(fx.recovery.newRecRoot);
  const mr = sha(Buffer.from('AEGIS_CCHS_RECOVER_V1'), Buffer.from('ton'), h.address.hash, u64(s.recNonce), newRoot, newRecRoot);
  assert.equal((await h.get('get_recovery_digest', [int(big(newRoot)), int(big(newRecRoot))])).rd.readBigNumber(), big(mr));
  const recBody = beginCell().storeUint(OP_RECOVER, 32).storeUint(0, 64).storeUint(big(newRoot), 256).storeUint(big(newRecRoot), 256)
    .storeRef(layerStream(wotsSign(0xff, 0, Number(s.recNonce), mr), authPath(rec, Number(s.recNonce))))
    .endCell();
  r = await h.send(recBody);
  assert.equal(r.exit, 0);
  console.log(`gas: recover ${r.gas}`);
  s = await h.state();
  assert.equal(s.root, big(newRoot));
  assert.equal(s.recRoot, big(newRecRoot));
  assert.deepEqual([s.nextIdx, s.epoch, s.recNonce, s.nonce], [0n, 1n, 1n, 2n]);

  // Old key material no longer authorizes anything.
  r = await h.send(execBody(0, 2, action('0.1'), true));
  assert.equal(r.exit, 203, 'old top root rejected after rotation');
});
