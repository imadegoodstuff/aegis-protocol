// Broadcast relay for the Aegis Bitcoin signet account.
//
// Spends of the CCHS-UTXO lineage use OP_CAT and OP_CHECKSIGFROMSTACK, which
// ordinary Bitcoin Core nodes treat as OP_SUCCESS and refuse to relay. Public
// APIs therefore cannot broadcast them. This process sits in front of a Bitcoin
// Inquisition node and exposes the minimum a browser wallet needs:
//
//   GET  /info          chain, height, whether op_cat / checksigfromstack are active
//   POST /tx            raw transaction hex → testmempoolaccept, then sendrawtransaction
//   GET  /tx/:txid      mempool / chain status as this node sees it
//
// No keys, no state, no wallet. It forwards consensus-valid transactions and
// reports what the node says. Anyone can run one (see Dockerfile); the wallet
// lets the user point at any relay.

import { createServer } from 'node:http';

const PORT = Number(process.env.PORT ?? 8332);
const RPC_URL = process.env.BITCOIN_RPC_URL ?? 'http://127.0.0.1:38332';
const RPC_USER = process.env.BITCOIN_RPC_USER ?? 'relay';
const RPC_PASS = process.env.BITCOIN_RPC_PASS ?? '';
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN ?? '*';
const MAX_BODY = 400_000;   // bytes of hex; an execFirst spend with a few inputs is well under this

async function rpc(method, params = []) {
  const r = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Basic ' + Buffer.from(`${RPC_USER}:${RPC_PASS}`).toString('base64') },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'relay', method, params }),
  });
  const j = await r.json().catch(() => ({ error: { message: `node returned ${r.status}` } }));
  if (j.error) throw Object.assign(new Error(j.error.message), { code: j.error.code });
  return j.result;
}

function send(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'access-control-allow-origin': ALLOW_ORIGIN,
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > MAX_BODY) { reject(new Error('body too large')); req.destroy(); } });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

async function info() {
  const [bc, dep] = await Promise.all([rpc('getblockchaininfo'), rpc('getdeploymentinfo')]);
  const active = n => Boolean(dep.deployments?.[n]?.active);
  return { chain: bc.chain, blocks: bc.blocks, headers: bc.headers, initialblockdownload: bc.initialblockdownload, op_cat: active('op_cat'), checksigfromstack: active('checksigfromstack') };
}

async function broadcast(hexRaw) {
  const hex = hexRaw.trim().replace(/^"|"$/g, '');
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2) throw new Error('body must be raw transaction hex');
  const [t] = await rpc('testmempoolaccept', [[hex]]);
  if (!t.allowed) throw new Error(`node rejects: ${t['reject-reason']}${t['reject-details'] ? ' — ' + t['reject-details'] : ''}`);
  const txid = await rpc('sendrawtransaction', [hex, 0]);
  return { txid, vsize: t.vsize, fees: t.fees };
}

async function txStatus(txid) {
  if (!/^[0-9a-f]{64}$/i.test(txid)) throw new Error('bad txid');
  try {
    const e = await rpc('getmempoolentry', [txid]);
    return { txid, inMempool: true, confirmed: false, vsize: e.vsize, fee: e.fees.base, time: e.time };
  } catch (err) {
    if (err.code !== -5) throw err;
  }
  try {
    const raw = await rpc('getrawtransaction', [txid, true]);
    return { txid, inMempool: false, confirmed: (raw.confirmations ?? 0) > 0, confirmations: raw.confirmations ?? 0, blockhash: raw.blockhash };
  } catch (err) {
    // Without -txindex a node only answers for mempool transactions; "unknown" here does
    // not mean unconfirmed. The wallet reads confirmations from a public explorer.
    if (err.code === -5) return { txid, inMempool: false, confirmed: null, known: false };
    throw err;
  }
}

createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  const url = new URL(req.url, 'http://relay');
  try {
    if (req.method === 'GET' && url.pathname === '/info') return send(res, 200, await info());
    if (req.method === 'POST' && url.pathname === '/tx') return send(res, 200, await broadcast(await readBody(req)));
    const m = url.pathname.match(/^\/tx\/([0-9a-fA-F]{64})$/);
    if (req.method === 'GET' && m) return send(res, 200, await txStatus(m[1].toLowerCase()));
    send(res, 404, { error: 'not found' });
  } catch (err) {
    send(res, 400, { error: err.message });
  }
}).listen(PORT, () => console.log(`relay on :${PORT} → ${RPC_URL}`));
