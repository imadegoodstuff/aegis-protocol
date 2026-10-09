// Key generation runs 1 024 WOTS+ leaves per tree. The wallet spreads them
// over Web Workers; the SDK offers the same pool with an in-process backend
// that works in node and in any browser, and accepts a host-supplied worker
// factory for parallelism.

import { CchsPool, type PoolOptions, type WorkerLike } from "../../wallet/src/aegis/cchsPool";
import { handleLeaves, type LeavesRequest } from "../../wallet/src/aegis/cchsWorkerCore";

export type { CchsPool, WorkerLike };

/** A worker that computes leaves on the calling thread (asynchronously, so callers are not blocked between chunks). */
export function inProcessWorker(): WorkerLike {
  const w: WorkerLike = {
    onmessage: null,
    postMessage(req) {
      void handleLeaves(req as LeavesRequest).then((r) => w.onmessage?.({ data: r }));
    },
    terminate() {},
  };
  return w;
}

/**
 * Create a pool. Without options the leaves are computed in-process (one
 * tree of 1 024 leaves takes about one second with the WASM hash cores).
 * Pass `spawn` to run them on real workers; a worker module is three lines:
 *
 *   import { handleLeaves } from '@aegis-protocol/sdk';
 *   self.onmessage = async (e) => self.postMessage(await handleLeaves(e.data));
 *
 *   createPool({ size: 8, spawn: () => new Worker(new URL('./cchs.worker.js', import.meta.url), { type: 'module' }) })
 */
export function createPool(opts: PoolOptions = {}): CchsPool {
  return new CchsPool({ size: opts.size ?? 1, spawn: opts.spawn ?? inProcessWorker });
}
