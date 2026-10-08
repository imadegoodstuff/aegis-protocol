// Browser Web Worker entry: one CCHS leaf-range computer per thread.
/// <reference lib="webworker" />

import { handleLeaves, type LeavesRequest } from './cchsWorkerCore';

self.onmessage = async (ev: MessageEvent<LeavesRequest>) => {
  const res = await handleLeaves(ev.data);
  if (res.leaves) (self as unknown as Worker).postMessage(res, [res.leaves.buffer as ArrayBuffer]);
  else (self as unknown as Worker).postMessage(res);
};
