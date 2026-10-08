// Parallel CCHS key generation.
//
// Leaves of a Merkle tree are independent, so the 1024 WOTS+ leaves of a
// tree are split into contiguous ranges and computed on N workers; the main
// thread then folds them into the tree (1023 node hashes, negligible).
// Everything produced here is byte-identical to the single-threaded `keygen`.

import { H, LEAVES, REC_H, type CchsKey, type CchsPublic, type Tree } from './cchs';
import { fastCchs, fastCompact } from './cchsFast';
import { leafBytes, type LeavesRequest, type LeavesResponse, type PoolVariant } from './cchsWorkerCore';

export interface WorkerLike {
  postMessage(msg: unknown, transfer?: Transferable[]): void;
  onmessage: ((ev: { data: LeavesResponse }) => void) | null;
  terminate(): void;
}

export interface PoolOptions {
  /** Number of workers. Default: hardware concurrency, 2..16. */
  size?: number;
  /** Worker factory. Default: the Vite module worker in ./cchsWorker.ts. */
  spawn?: () => WorkerLike;
}

type Pending = { resolve: (r: LeavesResponse) => void; reject: (e: Error) => void };

export class CchsPool {
  private workers: WorkerLike[] = [];
  private pending = new Map<number, Pending>();
  private seq = 0;
  private rr = 0;
  readonly size: number;

  constructor(opts: PoolOptions = {}) {
    const hc = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency || 4 : 4;
    this.size = Math.max(1, Math.min(16, opts.size ?? Math.max(2, hc)));
    const spawn = opts.spawn ?? (() => new Worker(new URL('./cchsWorker.ts', import.meta.url), { type: 'module' }) as unknown as WorkerLike);
    for (let i = 0; i < this.size; i++) {
      const w = spawn();
      w.onmessage = (ev) => {
        const p = this.pending.get(ev.data.id);
        if (!p) return;
        this.pending.delete(ev.data.id);
        ev.data.ok ? p.resolve(ev.data) : p.reject(new Error(ev.data.error ?? 'worker error'));
      };
      this.workers.push(w);
    }
  }

  private request(req: Omit<LeavesRequest, 'id'>): Promise<LeavesResponse> {
    const id = ++this.seq;
    const w = this.workers[this.rr++ % this.workers.length];
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      w.postMessage({ id, ...req });
    });
  }

  /** All `count` leaves of (layer, treeIdx), computed across the pool. */
  async leaves(key: CchsKey, variant: PoolVariant, layer: number, treeIdx: bigint, count: number): Promise<Uint8Array[]> {
    const chunks = Math.min(count, this.size * 2); // 2 chunks per worker smooths uneven cores
    const per = Math.ceil(count / chunks);
    const jobs: Promise<LeavesResponse>[] = [];
    for (let from = 0; from < count; from += per) {
      jobs.push(this.request({ variant, master: key.master, layer, treeIdx: treeIdx.toString(), from, to: Math.min(count, from + per) }));
    }
    const out: Uint8Array[] = new Array(count);
    for (const r of await Promise.all(jobs)) {
      const buf = r.leaves!;
      const n = leafBytes(variant);
      for (let i = 0; i < buf.length / n; i++) out[r.from! + i] = buf.subarray(i * n, i * n + n);
    }
    return out;
  }

  async tree(key: CchsKey, variant: PoolVariant, layer: number, treeIdx: bigint, height: number): Promise<Tree> {
    const [c, leaves] = await Promise.all([variant === 'C' ? fastCompact() : fastCchs(variant), this.leaves(key, variant, layer, treeIdx, 1 << height)]);
    return c.buildTreeFromLeaves(layer, treeIdx, leaves);
  }

  /**
   * Public key plus the trees needed for the first signature
   * (top layer, recovery tree, bottom subtree 0), all in one parallel pass.
   * `cache` receives the same keys `sign`/`signRecovery` look up.
   */
  async keygen(key: CchsKey, variant: PoolVariant, cache?: Map<string, Tree>, opts: { firstSubtree?: boolean } = {}): Promise<CchsPublic & { tookMs: number }> {
    const t0 = performance.now();
    const withBottom = opts.firstSubtree ?? true;
    const [top, rec, bottom0] = await Promise.all([
      this.tree(key, variant, 1, 0n, H),
      this.tree(key, variant, 0xff, 0n, REC_H),
      withBottom ? this.tree(key, variant, 0, 0n, H) : Promise.resolve(undefined),
    ]);
    cache?.set('1/0', top); cache?.set('ff/0', rec);
    if (bottom0) cache?.set('0/0', bottom0);
    return { root: top.root, recRoot: rec.root, tookMs: performance.now() - t0 };
  }

  terminate(): void {
    for (const w of this.workers) w.terminate();
    this.workers = [];
    for (const p of this.pending.values()) p.reject(new Error('pool terminated'));
    this.pending.clear();
  }
}

export { LEAVES };
