// Full account life cycle against the shipped EVM artifacts, in an in-process
// EVM (Cancun): publish the factory, predict and create an account for each
// parameter set, fund it, first signature (top layer), cached signatures,
// signer-chosen skips and the cross-subtree jump, the attacks that must fail,
// key rotation through recovery with per-epoch keys, a signature under the new
// epoch, and withdrawal of the remaining balance. Prints the whole-transaction
// cost of every step (intrinsic 21 000 + calldata + execution).
//
// Everything here is reproducible from the repository alone:
//   cd wallet && npm run evm-flow
//
// It uses wallet/src/aegis/cchsArtifacts.json (the bytes the wallet publishes),
// so it also checks that the shipped artifact matches the client.

import { VM } from '@ethereumjs/vm';
import { Common, Hardfork, Chain } from '@ethereumjs/common';
import { Address, Account, hexToBytes, bytesToHex } from '@ethereumjs/util';
import { encodeFunctionData, decodeFunctionResult, keccak256, type Hex } from 'viem';
import * as cchs from '../src/aegis/cchs.ts';
import { chainKey, epochKey, evmChainTag, predictAccount } from '../src/aegis/cchsAccount.ts';
import artifacts from '../src/aegis/cchsArtifacts.json' with { type: 'json' };

const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Cancun });
const vm = await VM.create({ common });
const relayer = Address.fromString('0x1000000000000000000000000000000000000001');
const recipient = Address.fromString('0x000000000000000000000000000000000000beef');
await vm.stateManager.putAccount(relayer, new Account(0n, 10n ** 24n));

const rows: { set: string; step: string; calldata: number; exec: bigint; total: bigint }[] = [];
let failures = 0;
const fail = (m: string) => { failures++; console.log(`FAIL ${m}`); };
const calldataGas = (cd: Uint8Array) => { let z = 0; for (const b of cd) if (b === 0) z++; return BigInt(z * 4 + (cd.length - z) * 16); };

async function send(to: Address | undefined, data: Uint8Array, value = 0n) {
  const r = await vm.evm.runCall({ caller: relayer, to, data, gasLimit: 30_000_000n, value });
  return { ok: !r.execResult.exceptionError, exec: r.execResult.executionGasUsed, err: r.execResult.exceptionError?.error, ret: r.execResult.returnValue, created: r.createdAddress, calldata: data.length, total: 21_000n + r.execResult.executionGasUsed + calldataGas(data) };
}
const encode = (abi: any, functionName: string, args: any[]) => hexToBytes(encodeFunctionData({ abi, functionName, args }));
const decode = (abi: any, functionName: string, ret: Uint8Array) => decodeFunctionResult({ abi, functionName, data: bytesToHex(ret) as Hex });
const balance = async (a: Address) => (await vm.stateManager.getAccount(a))?.balance ?? 0n;

// 1. factory exactly as the deterministic-deployment proxy publishes it: CREATE2 from the
//    proxy address with the fixed salt, so it lands at the same address as on every chain.
const fabi = artifacts.factory.abi;
const proxy = Address.fromString(artifacts.proxy);
await vm.stateManager.putAccount(proxy, new Account(0n, 10n ** 20n));
const fr = await vm.evm.runCall({ caller: proxy, data: hexToBytes(artifacts.factory.initCode as Hex), salt: hexToBytes(artifacts.salt as Hex), gasLimit: 30_000_000n, value: 0n });
if (fr.execResult.exceptionError) throw new Error('factory publish failed: ' + fr.execResult.exceptionError.error);
const factory = fr.createdAddress!;
if (factory.toString().toLowerCase() !== artifacts.factory.address.toLowerCase()) fail(`factory landed at ${factory}, artifact says ${artifacts.factory.address}`);
const fdep = { calldata: hexToBytes(artifacts.factory.initCode as Hex).length + 32, exec: fr.execResult.executionGasUsed, total: 21_000n + fr.execResult.executionGasUsed + calldataGas(hexToBytes(artifacts.factory.initCode as Hex)) + 32n * 16n };
rows.push({ set: '—', step: 'publish factory', calldata: fdep.calldata, exec: fdep.exec, total: fdep.total });

for (const variant of ['S', 'K'] as const) {
  const set = variant === 'S' ? 'S-20' : 'K-20';
  const c = cchs.forVariant(variant);
  const abi = artifacts.accountAbi;
  // The tree of this chain (chainId 1 in the VM): master -> chain key, as the wallet does.
  const master = chainKey({ master: new Uint8Array(32).fill(0x42) }, evmChainTag(1));
  const cache = new Map<string, cchs.Tree>();
  const pub = c.keygen(master, cache);
  const root = cchs.toHex(pub.root) as Hex, recRoot = cchs.toHex(pub.recRoot) as Hex;

  // 2. predict offline, create through the factory, check idempotence
  const offline = predictAccount(root, recRoot, variant);
  const pr = await send(factory, encode(fabi, 'predict', [root, recRoot, variant === 'S']));
  const onchainPredicted = decode(fabi, 'predict', pr.ret) as string;
  if (onchainPredicted.toLowerCase() !== offline.toLowerCase()) fail(`${set} offline prediction ${offline} != factory ${onchainPredicted}`);
  const dep = await send(factory, encode(fabi, 'deploy', [root, recRoot, variant === 'S']), 5n * 10n ** 18n);
  if (!dep.ok) throw new Error(`${set} deploy failed ${dep.err}`);
  const account = Address.fromString(decode(fabi, 'deploy', dep.ret) as string);
  if (account.toString().toLowerCase() !== offline.toLowerCase()) fail(`${set} deployed ${account} != predicted ${offline}`);
  rows.push({ set, step: 'create + fund account (factory.deploy)', calldata: dep.calldata, exec: dep.exec, total: dep.total });
  const again = await send(factory, encode(fabi, 'deploy', [root, recRoot, variant === 'S']));
  if (!again.ok || (decode(fabi, 'deploy', again.ret) as string).toLowerCase() !== offline.toLowerCase()) fail(`${set} deploy is not idempotent`);
  if (await balance(account) !== 5n * 10n ** 18n) fail(`${set} account not funded`);

  const view = async (fn: string, args: any[] = []) => { const r = await send(account, encode(abi, fn, args)); if (!r.ok) throw new Error(`${fn} reverted`); return decode(abi, fn, r.ret) as any; };

  // 3. signing helper (mirrors ProtectPanel.doSpend)
  let signed = -1; // write-ahead record of this "device"
  async function spend(opts: { key?: cchs.CchsKey; trees?: Map<string, cchs.Tree>; idx?: number; value?: bigint; target?: Address; tamper?: (s: cchs.CchsSignature) => void; noTop?: boolean; record?: boolean } = {}) {
    const key = opts.key ?? master, trees = opts.trees ?? cache;
    const epoch = Number(await view('epoch'));
    const nextIdx = Number(await view('nextIdx')), nonce = BigInt(await view('nonce'));
    const idx = opts.idx ?? Math.max(nextIdx, signed + 1);
    const value = opts.value ?? 10n ** 17n, target = opts.target ?? recipient;
    const needsTop = opts.noTop ? false : (await view('needsTopLayerAt', [BigInt(idx)])) as boolean;
    const onchain = (await view('digestAt', [BigInt(idx), target.toString(), value, '0x'])) as string;
    const m = c.executeDigest({ chainId: 1n, account: hexToBytes(account.toString()), nonce, idx: BigInt(idx), target: hexToBytes(target.toString()), value, dataHash: hexToBytes(keccak256('0x')) });
    if (bytesToHex(m) !== onchain) fail(`${set} client digest != digestAt at idx ${idx}`);
    if (opts.record !== false) signed = Math.max(signed, idx);
    const sig = c.sign(key, idx, m, !needsTop, trees);
    opts.tamper?.(sig);
    const fn = sig.l1 ? 'executeFirst' : 'execute';
    const args = [target.toString(), value, '0x', BigInt(idx), cchs.toAbiLayerSig(sig.l0), ...(sig.l1 ? [cchs.toAbiLayerSig(sig.l1)] : [])];
    const r = await send(account, encode(abi, fn, args));
    return { ...r, idx, needsTop, epoch };
  }

  // 4. first signature in subtree 0, then cached
  let r = await spend(); if (!r.ok) fail(`${set} first signature rejected: ${r.err}`);
  rows.push({ set, step: 'first signature in a subtree (executeFirst)', calldata: r.calldata, exec: r.exec, total: r.total });
  r = await spend(); if (!r.ok) fail(`${set} cached signature rejected: ${r.err}`);
  rows.push({ set, step: 'cached subtree (execute)', calldata: r.calldata, exec: r.exec, total: r.total });

  // 5. signer-chosen index: skip, jump, then everything that must fail
  r = await spend({ idx: 9 }); if (!r.ok || Number(await view('nextIdx')) !== 10) fail(`${set} skip to 9`);
  r = await spend({ idx: 1024 }); if (!r.ok || !r.needsTop) fail(`${set} jump to subtree 1 with top layer`);
  rows.push({ set, step: 'jump to a fresh subtree (executeFirst)', calldata: r.calldata, exec: r.exec, total: r.total });
  r = await spend({ idx: 1030, noTop: true }); if (!r.ok) fail(`${set} cached signature in subtree 1`);
  if ((await spend({ idx: 1030, record: false })).ok) fail(`${set} INDEX REUSE ACCEPTED`);
  if ((await spend({ idx: 3, record: false })).ok) fail(`${set} BACKWARD INDEX ACCEPTED`);
  if ((await spend({ idx: 2048, noTop: true, record: false })).ok) fail(`${set} FRESH SUBTREE WITHOUT TOP LAYER ACCEPTED`);
  if ((await spend({ record: false, tamper: (s) => { s.l0.wots[5][0] ^= 1; } })).ok) fail(`${set} TAMPERED CHAIN VALUE ACCEPTED`);
  if ((await spend({ record: false, tamper: (s) => { s.l0.auth[2][0] ^= 1; } })).ok) fail(`${set} TAMPERED AUTH PATH ACCEPTED`);

  // 6. rotation: recovery to epoch 1 with keys derived from the same chain key
  const recNonce = Number(await view('recNonce'));
  const next = epochKey(master, 1);
  const nextCache = new Map<string, cchs.Tree>();
  const nextPub = c.keygen(next, nextCache);
  const rm = c.recoveryDigest({ chainId: 1n, account: hexToBytes(account.toString()), recNonce: BigInt(recNonce), newRoot: nextPub.root, newRecRoot: nextPub.recRoot });
  const rs = c.signRecovery(master, recNonce, rm, cache);
  const rot = await send(account, encode(abi, 'recover', [cchs.toHex(nextPub.root), cchs.toHex(nextPub.recRoot), rs.wots.map(cchs.toHex), rs.auth.map(cchs.toHex)]));
  if (!rot.ok) fail(`${set} rotation rejected: ${rot.err}`);
  rows.push({ set, step: 'key rotation (recover)', calldata: rot.calldata, exec: rot.exec, total: rot.total });
  if (Number(await view('epoch')) !== 1 || Number(await view('nextIdx')) !== 0) fail(`${set} epoch/nextIdx after rotation`);
  if ((await view('root')) !== cchs.toHex(nextPub.root)) fail(`${set} root not rotated`);
  // old keys are dead, even at a fresh index with their top layer
  if ((await spend({ record: false })).ok) fail(`${set} OLD EPOCH KEY ACCEPTED AFTER ROTATION`);
  // replaying the same rotation under the new epoch must fail (recNonce moved)
  if ((await send(account, encode(abi, 'recover', [cchs.toHex(nextPub.root), cchs.toHex(nextPub.recRoot), rs.wots.map(cchs.toHex), rs.auth.map(cchs.toHex)]))).ok) fail(`${set} ROTATION REPLAYED`);

  // 7. spend under epoch 1 (fresh index space: first signature carries the top layer), then withdraw everything
  signed = -1;
  r = await spend({ key: next, trees: nextCache }); if (!r.ok || !r.needsTop) fail(`${set} first signature under epoch 1: ${r.err}`);
  rows.push({ set, step: 'first signature after rotation (executeFirst)', calldata: r.calldata, exec: r.exec, total: r.total });
  const rest = await balance(account);
  r = await spend({ key: next, trees: nextCache, value: rest }); if (!r.ok) fail(`${set} withdrawal rejected: ${r.err}`);
  rows.push({ set, step: 'withdraw remaining balance (execute)', calldata: r.calldata, exec: r.exec, total: r.total });
  if (await balance(account) !== 0n) fail(`${set} balance not zero after withdrawal`);
}

console.log('\n| Set | Step | Calldata (B) | Execution gas | Total gas (21 000 + calldata + execution) |');
console.log('|---|---|---:|---:|---:|');
for (const x of rows) console.log(`| ${x.set} | ${x.step} | ${x.calldata.toLocaleString('en-US')} | ${Number(x.exec).toLocaleString('en-US')} | ${Number(x.total).toLocaleString('en-US')} |`);
console.log(`\nruntime code: S-20 ${artifacts.account.S.runtimeBytes} B, K-20 ${artifacts.account.K.runtimeBytes} B`);
if (failures) { console.log(`\n${failures} check(s) failed`); process.exit(1); }
console.log('\nfull life cycle passed for S-20 and K-20');
