// CCHS bound to WebAssembly hash cores (hash-wasm). Same bytes as the pure-JS
// `cchsS` / `cchsK`; roughly 2x faster per hash on 64-byte inputs. Used by the
// keygen workers and by the main thread for tree assembly.

import { createSHA256, createKeccak, type IHasher } from 'hash-wasm';
import { makeCchs, type Cchs, type HashFn, type Variant } from './cchs';

function bind(h: IHasher): HashFn {
  return (data: Uint8Array) => {
    h.init();
    h.update(data);
    return h.digest('binary').slice(); // hash-wasm reuses its output buffer
  };
}

const cache: Partial<Record<Variant, Promise<Cchs>>> = {};

/** WASM-backed CCHS instance for the given parameter set (memoized). */
export function fastCchs(variant: Variant): Promise<Cchs> {
  let p = cache[variant];
  if (!p) {
    p = (variant === 'S' ? createSHA256() : createKeccak(256)).then((h) => makeCchs(bind(h), variant));
    cache[variant] = p;
  }
  return p;
}
