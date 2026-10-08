// Request handler shared by the browser worker (cchsWorker.ts) and any other
// host (tests, worker_threads). Computes a contiguous range of WOTS+ leaves.

import type { Variant } from './cchs';
import { fastCchs } from './cchsFast';

export interface LeavesRequest {
  id: number;
  variant: Variant;
  master: Uint8Array;
  layer: number;
  treeIdx: string; // bigint as decimal string (structured clone of bigint is fine, string keeps JSON hosts simple)
  from: number;
  to: number;
}

export interface LeavesResponse {
  id: number;
  ok: boolean;
  from?: number;
  leaves?: Uint8Array; // (to - from) * 32 bytes, concatenated
  error?: string;
}

export async function handleLeaves(req: LeavesRequest): Promise<LeavesResponse> {
  try {
    const c = await fastCchs(req.variant);
    const leaves = c.leavesRange({ master: req.master }, req.layer, BigInt(req.treeIdx), req.from, req.to);
    const out = new Uint8Array(leaves.length * 32);
    for (let i = 0; i < leaves.length; i++) out.set(leaves[i], i * 32);
    return { id: req.id, ok: true, from: req.from, leaves: out };
  } catch (e) {
    return { id: req.id, ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
